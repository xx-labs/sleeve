bench-tweak:
	go test ./wots/... -count=100 -bench="BenchmarkTweak*" -run='^$$' 2>&1 | tee out.txt
	@echo ""
	@benchstat out.txt
	@rm out.txt

bench-sleeve:
	go test ./wallet/... -count=100 -bench="BenchmarkSleeve*" -run='^$$' 2>&1 | tee out.txt
	@echo ""
	@benchstat out.txt
	@rm out.txt
