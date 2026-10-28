# Qualification harness, first slice

Implemented: capture.py retains an exact source archive, its digest, the read-only
doctor report, report digest, timestamps, exit code and explicit unproven gates.
Run as the development user; use sudo only when a required observation is unreadable.
Evidence is local and excluded from source archives and Git. It is not certification.

Lab recipe:
1. Operator-owned licensed AlmaLinux/cPanel VM; record actual versions using doctor.
2. Retain VM recovery point and verify console access and restoration on a disposable
   instance. Record the provider/image/disk IDs locally. No restore is yet verified.
3. Reserve isolated test bindings and DNS. Create two unrelated synthetic accounts
   and static/PHP/protected/TLS fixtures only after recording the recovery method.
4. Record G0-A callers, commands, expected/actual observations, package set, source
   and artifact hashes. Include native WHM restart/status, chkservd, reboot,
   Apache rebuild and an EA4 transaction. Preserve original vendor file hashes.
5. Proceed to G0-B/C/H only after the service premise is resolved, then D/E/F/G.
6. Each test needs timestamps, exact platform/fixture identity, sanitized transcript,
   exit status and independent reviewer. Missing evidence means unproven.

No restart/reboot/account creation, fault injection or restore is implemented in
capture.py. The operator has designated this host as empty and for testing;
snapshot/console/restore readiness remains unverified. Destructive qualification
is not authorized merely by a successful baseline capture.

Native Apache control-path harness: service_probe.py defaults to observation.
Explicit --action native-graceful or --action whm-restart with --lab-empty-host
performs a real restart on the narrowly checked empty test host. See
../../docs/service-control-experiments.md and verify_service.py. These are
development experiments and do not alter the production CLI's audit-only contract.

The separate disable_probe.py temporarily disables Apache and its monitor on the
explicitly acknowledged empty lab, records native/WHM behavior, then restores the
initial enabled/monitored/running state. It arms a fixed independent recovery timer
before mutation and disarms only after recovery verification. See
../../docs/disabled-apache-experiment.md and verify_disable.py. This is not an
installer and has not been qualified for customer servers or crash recovery.
