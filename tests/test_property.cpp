#include "framework.hpp"

#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "nof/canonical.hpp"
#include "nof/synthetic.hpp"
#include "support.hpp"

using namespace nof;

namespace {

// Deterministic xorshift generator: property runs are reproducible by seed.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  std::uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  std::size_t below(std::size_t bound) {
    if (bound == 0) {
      return 0;
    }
    return static_cast<std::size_t>(next() % bound);
  }

 private:
  std::uint64_t state_;
};

std::string selector_for(int index) {
  return "dir=ingress,proto=tcp,dst=10.5." + std::to_string(index / 200) + "." +
         std::to_string(index % 200) + ":443";
}

// Runs a seeded operation sequence against a fabric and verifies the invariant
// set after every step.
void run_sequence(Fabric& fabric, const synthetic::Scenario& scenario,
                  const synthetic::ScenarioOptions& options, std::uint64_t seed, int steps) {
  Rng rng(seed);
  std::vector<AssignmentId> live;
  for (int step = 0; step < steps; ++step) {
    const std::size_t choice = rng.below(6);
    if (choice == 0) {
      PlacementRequest request =
          synthetic::make_request(scenario, options, "prop-" + std::to_string(step));
      request.scope.selector = selector_for(step);
      ApplyOptions apply_options;
      apply_options.request_id = request.request_id;
      const auto record = fabric.apply(request, apply_options);
      if (record.ok()) {
        live.push_back(record.value().id);
      }
    } else if (choice == 1 && !live.empty()) {
      const std::size_t index = rng.below(live.size());
      RevokeRequest revoke;
      revoke.request_id = RequestId::from_validated("prop-revoke-" + std::to_string(step));
      revoke.assignment = live[index];
      revoke.reason = ReasonCode::Revoked;
      (void)fabric.revoke(revoke);
    } else if (choice == 2 && !live.empty()) {
      const std::size_t index = rng.below(live.size());
      const auto record = fabric.get_assignment(live[index]);
      if (record.ok()) {
        EffectReport effect;
        effect.request_id = RequestId::from_validated("prop-effect-" + std::to_string(step));
        effect.assignment = record.value().id;
        effect.attempt = record.value().attempt;
        effect.generation = record.value().generation;
        effect.fence = record.value().fence;
        effect.incarnation = record.value().incarnation;
        effect.capability_generation = record.value().binding.capability;
        effect.outcome = rng.below(2) == 0 ? EffectOutcome::Applied : EffectOutcome::Unknown;
        effect.observed_at = Micros::raw(1500000 + step);
        effect.provenance.source = SourceId::from_validated("syn-enforcement");
        effect.provenance.sequence = static_cast<std::uint64_t>(step + 1);
        (void)fabric.report_effect(effect);
      }
    } else if (choice == 3) {
      (void)fabric.revalidate(nullptr);
    } else if (choice == 4) {
      (void)fabric.plan(synthetic::make_request(scenario, options,
                                                "prop-plan-" + std::to_string(step)));
    } else {
      (void)fabric.stats();
      (void)fabric.state_digest();
    }
    const InvariantReport report = fabric.verify_invariants();
    NOF_CHECK(report.clean);
    if (!report.clean) {
      NOF_FAIL(report.render());
      return;
    }
  }
}

}  // namespace

NOF_TEST(property, seeded_sequences_preserve_invariants) {
  for (std::uint64_t seed = 1; seed <= 4; ++seed) {
    support::Fixture fixture("prop-" + std::to_string(seed));
    run_sequence(fixture.ref(), fixture.scenario, fixture.options, seed, 60);
    NOF_CHECK(!fixture.ref().state_digest().is_zero());
  }
}

NOF_TEST(property, identical_inputs_produce_identical_state) {
  const std::string first_path = support::store_path("prop-det-1");
  const std::string second_path = support::store_path("prop-det-2");
  support::remove_store(first_path);
  support::remove_store(second_path);
  std::string first_digest;
  std::string second_digest;
  std::string first_export;
  std::string second_export;
  for (int run = 0; run < 2; ++run) {
    synthetic::ScenarioOptions options;
    options.hosts = 2;
    options.observed_at = Micros::raw(1000000);
    options.valid_until = Micros::raw(2000000);
    const synthetic::Scenario scenario = synthetic::make_scenario(options);
    FabricConfig config;
    config.store_path = run == 0 ? first_path : second_path;
    config.clock = std::make_shared<ManualClock>(Micros::raw(1500000));
    config.boot_id = BootId::from_validated("cccccccccccccccccccccccccccccccc");
    Fabric fabric(std::move(config));
    NOF_CHECK_OK(fabric.start());
    for (const FunctionDescriptor& function : scenario.functions) {
      NOF_CHECK_OK(fabric.register_function(function));
    }
    NOF_CHECK_OK(fabric.ingest_policy(scenario.policy));
    NOF_CHECK_OK(fabric.ingest_topology(scenario.topology));
    NOF_CHECK_OK(fabric.ingest_capabilities(scenario.capabilities));
    NOF_CHECK_OK(fabric.ingest_observations(scenario.observations));
    NOF_CHECK_OK(fabric.grant_authority(scenario.authority));
    run_sequence(fabric, scenario, options, 7, 25);
    std::string document;
    NOF_CHECK_OK(fabric.export_canonical(ExportFormat::CanonicalJson, document));
    const std::string digest = fabric.state_digest().hex();
    if (run == 0) {
      first_digest = digest;
      first_export = document;
    } else {
      second_digest = digest;
      second_export = document;
    }
    NOF_CHECK_OK(fabric.shutdown());
  }
  NOF_CHECK_EQ(first_digest, second_digest);
  NOF_CHECK_EQ(first_export, second_export);
  support::remove_store(first_path);
  support::remove_store(second_path);
}

NOF_TEST(property, acknowledgement_never_becomes_verified_application) {
  support::Fixture fixture("prop-ack");
  const auto applied = fixture.apply("prop-ack-1");
  NOF_CHECK_OK(applied);
  for (int index = 0; index < 5; ++index) {
    EffectReport report;
    report.request_id = RequestId::from_validated("prop-ack-unknown-" + std::to_string(index));
    report.assignment = applied.value().id;
    report.attempt = applied.value().attempt;
    report.generation = applied.value().generation;
    report.fence = applied.value().fence;
    report.incarnation = applied.value().incarnation;
    report.capability_generation = applied.value().binding.capability;
    report.outcome = EffectOutcome::Unknown;
    report.observed_at = Micros::raw(1500000 + index);
    report.provenance.source = SourceId::from_validated("syn-enforcement");
    report.provenance.sequence = static_cast<std::uint64_t>(index + 1);
    NOF_CHECK_OK(fixture.ref().report_effect(report));
    const auto record = fixture.ref().get_assignment(applied.value().id);
    NOF_CHECK_OK(record);
    NOF_CHECK_EQ(record.value().state, AssignmentState::Dispatched);
  }
  NOF_CHECK_EQ(fixture.ref().stats().effects_applied, 0u);
  NOF_CHECK_EQ(fixture.ref().stats().effects_unknown, 1u);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(property, exports_and_explanations_are_byte_stable) {
  support::Fixture fixture("prop-stable");
  NOF_CHECK_OK(fixture.apply("prop-stable-1"));
  std::string first_json;
  std::string second_json;
  NOF_CHECK_OK(fixture.ref().export_canonical(ExportFormat::CanonicalJson, first_json));
  NOF_CHECK_OK(fixture.ref().export_canonical(ExportFormat::CanonicalJson, second_json));
  NOF_CHECK_EQ(first_json, second_json);
  auto parsed = JsonReader(first_json).parse();
  NOF_CHECK_OK(parsed);

  const auto first_plan = fixture.ref().plan(fixture.request("prop-stable-2"));
  const auto second_plan = fixture.ref().plan(fixture.request("prop-stable-2"));
  NOF_CHECK_OK(first_plan);
  NOF_CHECK_OK(second_plan);
  NOF_CHECK_EQ(render_explanation(first_plan.value().explanation),
               render_explanation(second_plan.value().explanation));
  NOF_CHECK_EQ(first_plan.value().plan.plan_digest.hex(),
               second_plan.value().plan.plan_digest.hex());
}
