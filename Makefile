VENV=.venv/bin
IFACE?=en0
ATTACKER?=

.PHONY: help setup test sim replay sensor clean
help:
	@echo "make setup     install deps into .venv"
	@echo "make test      run unit + integration tests"
	@echo "make sim       generate the synthetic attack pcap"
	@echo "make replay    run the IDS over the attack pcap (no root)"
	@echo "make sensor    live capture on IFACE=$(IFACE) (needs sudo)"
	@echo "make clean     remove logs and caches"
setup:
	python3 -m venv .venv && $(VENV)/pip install -q -r requirements.txt
test:
	$(VENV)/python -m pytest tests/ -q
sim:
	$(VENV)/python scripts/gen_attack_pcap.py
replay: sim
	$(VENV)/python -m ids.sensor -r logs/attack_sim.pcap --quiet --summary-json logs/summary.json
sensor:
	sudo $(VENV)/python -m ids.sensor -i $(IFACE) $(if $(ATTACKER),-f "host $(ATTACKER)",) --min-severity low
clean:
	rm -f logs/*.jsonl logs/*.pcap logs/*.json; find . -name __pycache__ -type d -exec rm -rf {} +
