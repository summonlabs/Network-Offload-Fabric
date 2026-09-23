// Downstream consumer of the installed Network Offload Fabric package.
//
// It uses the synthetic fixtures shipped with the runtime so the consumer can
// run without hardware; nothing here proves hardware behaviour.
#include <cstdio>
#include <memory>
#include <string>

#include <nof/fabric.hpp>
#include <nof/synthetic.hpp>
#include <nof/version.hpp>

int main() {
  nof::FabricConfig config;
  config.store_path = "nof-consumer.nofjournal";
  config.clock = std::make_shared<nof::ManualClock>(nof::Micros::raw(1500000));
  config.boot_id = nof::BootId::from_validated("11111111111111111111111111111111");

  nof::synthetic::ScenarioOptions options;
  options.hosts = 2;
  options.observed_at = nof::Micros::raw(1000000);
  options.valid_until = nof::Micros::raw(2000000);
  const nof::synthetic::Scenario scenario = nof::synthetic::make_scenario(options);

  nof::Fabric fabric(std::move(config));
  if (!fabric.start().ok()) {
    std::fprintf(stderr, "nof_consumer: fabric start failed\n");
    return 2;
  }
  for (const nof::FunctionDescriptor& function : scenario.functions) {
    (void)fabric.register_function(function);
  }
  (void)fabric.ingest_policy(scenario.policy);
  (void)fabric.ingest_topology(scenario.topology);
  (void)fabric.ingest_capabilities(scenario.capabilities);
  (void)fabric.ingest_observations(scenario.observations);
  (void)fabric.grant_authority(scenario.authority);

  nof::PlacementRequest request =
      nof::synthetic::make_request(scenario, options, "consumer-req-1");
  nof::ApplyOptions apply_options;
  apply_options.request_id = request.request_id;
  const auto applied = fabric.apply(request, apply_options);
  if (!applied.ok()) {
    std::fprintf(stderr, "nof_consumer: apply refused: %s\n",
                 nof::to_string(applied.error()).c_str());
    return 3;
  }

  nof::EffectReport effect;
  effect.request_id = nof::RequestId::from_validated("consumer-eff-1");
  effect.assignment = applied.value().id;
  effect.attempt = applied.value().attempt;
  effect.generation = applied.value().generation;
  effect.fence = applied.value().fence;
  effect.incarnation = applied.value().incarnation;
  effect.capability_generation = applied.value().binding.capability;
  effect.outcome = nof::EffectOutcome::Applied;
  effect.observed_at = nof::Micros::raw(1500000);
  effect.provenance.source = nof::SourceId::from_validated("consumer-enforcement");
  effect.provenance.sequence = 1;
  const auto verified = fabric.report_effect(effect);
  if (!verified.ok() || verified.value().state != nof::AssignmentState::AppliedVerified) {
    std::fprintf(stderr, "nof_consumer: effect was not verified as applied\n");
    return 4;
  }

  std::string document;
  if (!fabric.export_canonical(nof::ExportFormat::CanonicalJson, document).ok()) {
    std::fprintf(stderr, "nof_consumer: canonical export failed\n");
    return 5;
  }
  const nof::InvariantReport invariants = fabric.verify_invariants();
  if (!invariants.clean) {
    std::fprintf(stderr, "nof_consumer: invariants violated\n");
    return 6;
  }
  std::printf("nof_consumer: version=%s assignment=%s device=%s state=%s digest=%s bytes=%zu\n",
              std::string(nof::version_string()).c_str(), applied.value().id.value().c_str(),
              applied.value().device.value().c_str(),
              nof::to_string(verified.value().state), fabric.state_digest().hex().c_str(),
              document.size());
  (void)fabric.shutdown();
  (void)std::remove("nof-consumer.nofjournal");
  (void)std::remove("nof-consumer.nofjournal.snapshot");
  return 0;
}
