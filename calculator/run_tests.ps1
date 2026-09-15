# ==============================================================================
# Assemble Calculator Automated Verification Suite
# ==============================================================================

Write-Host "Running Assemble Assembly Calculator Verification..." -ForegroundColor Cyan

$testVectors = @(
    @{ Input = "15 + 27"; Expected = "= 42"; Name = "Addition (15 + 27)" },
    @{ Input = "100 - 35"; Expected = "= 65"; Name = "Subtraction (100 - 35)" },
    @{ Input = "12 * 12"; Expected = "= 144"; Name = "Multiplication (12 * 12)" },
    @{ Input = "100 / 7"; Expected = "= 14.285714"; Name = "Fractional Division (100 / 7)" },
    @{ Input = "1/3"; Expected = "= 0.333333"; Name = "Repeating Decimal Division (1/3)" },
    @{ Input = "9/7"; Expected = "= 1.285714"; Name = "Decimal Division (9/7)" },
    @{ Input = "1215646581523853/2"; Expected = "= 607823290761926.5"; Name = "Large Dividend Division (1215646581523853/2)" },
    @{ Input = "1215646581523853*15465123186541"; Expected = "Error: Arithmetic overflow (result exceeds 64-bit integer range)!"; Name = "Checked 64-Bit Multiplication Overflow" },
    @{ Input = "100 % 7"; Expected = "= 2"; Name = "Modulo Remainder (100 % 7)" },
    @{ Input = "|-99|"; Expected = "= 99"; Name = "Branchless Absolute Value (|-99|)" },
    @{ Input = "42 / 0"; Expected = "Error: Division by zero!"; Name = "Division by Zero Guard (42 / 0)" },
    @{ Input = "42 % 0"; Expected = "Error: Modulo by zero!"; Name = "Modulo by Zero Guard (42 % 0)" },
    @{ Input = "-50 + 20"; Expected = "= -30"; Name = "Signed Arithmetic (-50 + 20)" },
    @{ Input = "-1/3"; Expected = "= -0.333333"; Name = "Negative Fractional Division (-1/3)" },
    @{ Input = "10/2"; Expected = "= 5"; Name = "Exact Integer Division (10/2)" }
)

$inputs = ($testVectors | ForEach-Object { $_.Input }) -join "`n"
$inputs += "`nquit`n"

$rawOutput = $inputs | .\calculator\calculator.exe

$allPassed = $true
foreach ($test in $testVectors) {
    if ($rawOutput -match [regex]::Escape($test.Expected)) {
        Write-Host "  [PASS] $($test.Name): Found '$($test.Expected)'" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($test.Name): Expected '$($test.Expected)'" -ForegroundColor Red
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Host "`nAll $($testVectors.Count) Assembly Calculator tests passed successfully!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nSome tests failed!" -ForegroundColor Red
    exit 1
}
