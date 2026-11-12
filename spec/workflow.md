# Development workflow (spec driven)

The source of truth is `spec/SPEC.md`. Code follows the spec. If the code needs
to differ, change the spec first, in the same pull request.

## Layers

| File | What it holds | Who writes it |
|---|---|---|
| `spec/SPEC.md` | Product spec: requirements (FR/NFR/S IDs), milestones, rules | Human, agents propose changes |
| `spec/decisions/NNNN-*.md` | One decision each: options, preferred choice, status | Research agent proposes, human accepts |
| `spec/milestones/MN/spec.md` | The slice of SPEC.md this milestone covers, acceptance criteria as checkboxes | Planner agent |
| `spec/milestones/MN/plan.md` | Design: crates, types, traits, test strategy, facts verified (SPEC section 15) | Planner agent |
| `spec/milestones/MN/tasks.md` | Ordered tasks, each one PR sized (under ~400 lines), each with its test | Planner agent |

## Loop for one milestone

1. **Specify.** Copy the milestone's acceptance criteria from SPEC.md section 12
   into `spec/milestones/MN/spec.md`. Link every FR/NFR/S ID it touches.
2. **Verify facts.** For each SPEC section 15 item the milestone relies on,
   check it (docs, source, a small spike). Tick it in SPEC.md with a link.
3. **Plan.** Write `plan.md`. Then `tasks.md`: small tasks, with dependencies
   marked, so independent tasks can run in parallel.
4. **Gate: decisions.** If a task needs an answer that is not in SPEC.md or
   `spec/decisions/`, it is blocked. See "Blocked on a decision" below.
5. **Implement.** One task per branch (`mN/tNN-short-name`). Test first.
   `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace` must pass.
6. **Review.** A separate reviewer agent reads the diff against the spec and the
   security rules. Fix, then merge.
7. **Accept.** When all tasks are done, check every acceptance box in
   `spec.md` with evidence (test name or command output). Update SPEC.md.

## Blocked on a decision

Do not guess. Instead:

1. Copy `spec/decisions/0000-template.md` to the next free number.
   Status: `research`.
2. A research agent (high effort) fills in context, options with trade offs,
   and a preferred option with reasons. Status: `proposed`.
3. The human sets status `accepted` (or picks another option). Only then do
   tasks that depend on it continue. Other tasks keep going meanwhile.
4. Update SPEC.md section 16 to point at the decision record.
