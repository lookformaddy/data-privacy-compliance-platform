.PHONY: test demo scan mask

test:
	PYTHONPATH=src python -m pytest tests/ -q

demo:
	PYTHONPATH=src python -m privacy_platform.cli demo

scan:
	PYTHONPATH=src python -m privacy_platform.cli scan --input examples/sample_dataset.csv
