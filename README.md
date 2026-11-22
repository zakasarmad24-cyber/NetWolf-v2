# NetWolf v2 - experiment data for the paper

Anonymized logs of the three real-device experiments and the results of the trace-driven evaluation
reported in the paper "NetWolf v2: Detecting Evil Twin Relays from the Legitimate Access Point".

| Folder | Experiment |
|---|---|
| `Exp-01_2026-11-22_13-27-33` | Attack, 3 devices, 29 min (relay D2) |
| `Exp-02_2026-11-22_14-42-32` | Normal use, 3 devices, 60 min |
| `Exp-03_2026-11-22_17-06-29` | Attack, 6 devices, 54 min (relay D4) |
| `evaluation` | Output of NetWolfV2Eval (Table 5, Fig. 5, scenarios, sensitivity) |

Each experiment folder contains `data/devices.csv` (one row per device per second), `data/summary.csv`
(one row per snapshot), `data/events.csv` and `experiment.txt` (the ground truth used by the evaluator).
Devices appear only as aliases (D1, D2, ...); no IP or MAC addresses or device names are included.

To reproduce the evaluation, copy the three `Exp-*` folders into one folder and run
`NetWolfV2Eval <that folder>` (seed 2026).
