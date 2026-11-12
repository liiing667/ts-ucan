import { emailCapability, EMAIL_SEMANTICS } from "./capability/email"
import { alice, bob, mallory } from "./fixtures"
import { all, ProofBudgetExceededError } from "../src"
import * as ucans from "../src"


describe("proof graph budget", () => {

  const alicesEmail = {
    capability: emailCapability("alice@email.com"),
    rootIssuer: alice.did(),
  }

  // Two alternating signers so every parent's issuer matches its proof's audience.
  const signers = [ bob, mallory ]

  /**
   * Builds a linear chain of `levels` proof links. The root is issued by alice
   * to bob and delegates her email capability; every subsequent level reuses
   * the previous UCAN as its single proof.
   */
  async function buildLinearChain(levels: number): Promise<ucans.Ucan> {
    let current = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    for (let i = 0; i < levels; i++) {
      const issuer = signers[ i % 2 ]
      const audience = signers[ (i + 1) % 2 ].did()
      current = await ucans.build({
        issuer,
        audience,
        capabilities: [ emailCapability("alice@email.com") ],
        proofs: [ ucans.encode(current) ]
      })
    }

    return current
  }

  /**
   * Builds a proof DAG where every level references the same previous UCAN
   * twice while carrying several attenuations. Every attenuation is checked
   * against every proof, so the shared proof is expanded once per branch and
   * the number of evaluated UCANs grows exponentially with the depth.
   */
  async function buildSharedProofDag(levels: number): Promise<ucans.Ucan> {
    const attenuations = [
      emailCapability("alice@email.com"),
      emailCapability("carol@email.com"),
    ]
    let current = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: attenuations
    })

    for (let i = 0; i < levels; i++) {
      const issuer = signers[ i % 2 ]
      const audience = signers[ (i + 1) % 2 ].did()
      const encoded = ucans.encode(current)
      current = await ucans.build({
        issuer,
        audience,
        capabilities: attenuations,
        proofs: [ encoded, encoded ]
      })
    }

    return current
  }

  function audienceFor(levels: number): string {
    return signers[ levels % 2 ].did()
  }

  it("accepts a normal delegation chain within the default budget", async () => {
    const ucan = await buildLinearChain(10)

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: audienceFor(10),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(true)
  })

  it("still verifies a legal `prf:*` redelegation with multiple proofs", async () => {
    const leafUcanA = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("ignore-me@email.com") ]
    })
    const leafUcanB = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ ucans.capability.prf(ucans.SUPERUSER, ucans.ability.REDELEGATE) ],
      proofs: [ ucans.encode(leafUcanA), ucans.encode(leafUcanB) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(true)
  })

  it("bounds a shared-proof DAG that would otherwise expand exponentially", async () => {
    const dag = await buildSharedProofDag(5)

    // Fully enumerating the delegation chains expands every shared-proof
    // branch, which would grow exponentially without a budget. A small budget
    // keeps this test fast while still exercising the exponential shape.
    const outputs = await all(
      ucans.delegationChains(EMAIL_SEMANTICS, dag, async () => false, { maxEvaluations: 50 })
    )

    const budgetError = outputs.find(o => o instanceof ProofBudgetExceededError)
    expect(budgetError).toBeInstanceOf(ProofBudgetExceededError)
    if (!(budgetError instanceof ProofBudgetExceededError)) return

    expect(budgetError.limit).toEqual("maxEvaluations")
    expect(budgetError.budget.maxEvaluations).toEqual(50)
    expect(budgetError.evaluations).toBeGreaterThan(50)
    // the depth limit must not be the one that tripped first
    expect(budgetError.depth).toBeLessThanOrEqual(budgetError.budget.maxDepth)
  })

  it("fails structurally in verify when a shared-proof DAG exhausts the budget", async () => {
    const dag = await buildSharedProofDag(3)

    // Requesting an ungranted capability forces full graph traversal, so the
    // budget is exhausted before the (non-existent) chain can be found.
    const result = await ucans.verify(ucans.encode(dag), {
      audience: audienceFor(3),
      requiredCapabilities: [ {
        capability: emailCapability("nobody@email.com"),
        rootIssuer: alice.did()
      } ],
      proofGraphBudget: { maxEvaluations: 20 }
    })

    expect(result.ok).toEqual(false)
    if (result.ok) return

    const budgetError = result.error.find(e => e instanceof ProofBudgetExceededError)
    expect(budgetError).toBeInstanceOf(ProofBudgetExceededError)
    if (!(budgetError instanceof ProofBudgetExceededError)) return

    expect(budgetError.limit).toEqual("maxEvaluations")
    expect(budgetError.budget.maxEvaluations).toEqual(20)
    expect(budgetError.evaluations).toBeGreaterThan(20)
    // the depth limit must not be the one that tripped first
    expect(budgetError.depth).toBeLessThanOrEqual(budgetError.budget.maxDepth)
  })

  it("fails structurally when a custom maxDepth is exceeded", async () => {
    const ucan = await buildLinearChain(6)

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: audienceFor(6),
      requiredCapabilities: [ alicesEmail ],
      proofGraphBudget: { maxDepth: 3 }
    })

    expect(result.ok).toEqual(false)
    if (result.ok) return

    const budgetError = result.error.find(e => e instanceof ProofBudgetExceededError)
    expect(budgetError).toBeInstanceOf(ProofBudgetExceededError)
    if (!(budgetError instanceof ProofBudgetExceededError)) return

    expect(budgetError.limit).toEqual("maxDepth")
    expect(budgetError.depth).toEqual(4)
    expect(budgetError.budget.maxDepth).toEqual(3)
  })

  it("fails structurally when a custom maxEvaluations is exceeded", async () => {
    const ucan = await buildLinearChain(4)

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: audienceFor(4),
      requiredCapabilities: [ alicesEmail ],
      proofGraphBudget: { maxEvaluations: 3 }
    })

    expect(result.ok).toEqual(false)
    if (result.ok) return

    const budgetError = result.error.find(e => e instanceof ProofBudgetExceededError)
    expect(budgetError).toBeInstanceOf(ProofBudgetExceededError)
    if (!(budgetError instanceof ProofBudgetExceededError)) return

    expect(budgetError.limit).toEqual("maxEvaluations")
    expect(budgetError.evaluations).toEqual(4)
    expect(budgetError.budget.maxEvaluations).toEqual(3)
  })

  it("never reports success when the budget is exhausted mid-verification", async () => {
    // Even though the chain legitimately delegates the required capability,
    // a tiny budget must turn the result into a failure.
    const ucan = await buildLinearChain(3)

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: audienceFor(3),
      requiredCapabilities: [ alicesEmail ],
      proofGraphBudget: { maxEvaluations: 2 }
    })

    expect(result.ok).toEqual(false)
    if (result.ok) return
    expect(result.error.some(e => e instanceof ProofBudgetExceededError)).toEqual(true)
  })

  it("rejects an invalid proof graph budget with a TypeError", async () => {
    const ucan = await buildLinearChain(1)

    await expect(ucans.verify(ucans.encode(ucan), {
      audience: audienceFor(1),
      requiredCapabilities: [ alicesEmail ],
      proofGraphBudget: { maxDepth: -1 }
    })).rejects.toBeInstanceOf(TypeError)

    await expect(ucans.verify(ucans.encode(ucan), {
      audience: audienceFor(1),
      requiredCapabilities: [ alicesEmail ],
      proofGraphBudget: { maxEvaluations: 0 }
    })).rejects.toBeInstanceOf(TypeError)
  })

  it("exposes the budget failure through delegationChains as well", async () => {
    const ucan = await buildLinearChain(5)

    const outputs = await all(
      ucans.delegationChains(EMAIL_SEMANTICS, ucan, async () => false, { maxDepth: 2 })
    )

    const budgetError = outputs.find(o => o instanceof ProofBudgetExceededError)
    expect(budgetError).toBeInstanceOf(ProofBudgetExceededError)
    if (!(budgetError instanceof ProofBudgetExceededError)) return

    expect(budgetError.limit).toEqual("maxDepth")
    expect(budgetError.depth).toEqual(3)
  })

  it("keeps revocation checks working alongside the budget", async () => {
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    const revoked = new Set([ ucans.encode(leafUcan) ])

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ],
      isRevoked: async candidate => revoked.has(ucans.encode(candidate))
    })

    expect(result.ok).toEqual(false)
    if (result.ok) return
    expect(result.error.some(e => e.message.includes("Revoked"))).toEqual(true)
    expect(result.error.some(e => e instanceof ProofBudgetExceededError)).toEqual(false)
  })

})
