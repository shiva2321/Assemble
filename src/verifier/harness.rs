use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::assembler::assemble;
use crate::emulator::StepTracer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub initial_registers: HashMap<String, u64>,
    pub expected_registers: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub steps_executed: usize,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub results: Vec<TestResult>,
}

pub fn run_verification(assembly_code: &str, tests: &[TestCase]) -> Result<VerificationReport, String> {
    let bytes = assemble(assembly_code)?;

    let mut results = Vec::new();
    let mut passed_count = 0;

    for test in tests {
        let mut tracer = StepTracer::new();
        for (reg, &val) in &test.initial_registers {
            tracer.set_initial_register(reg, val);
        }

        let steps = tracer.trace(&bytes, 0x400000)?;
        let mut mismatches = Vec::new();

        // Check if registers match expected
        for (exp_reg, &exp_val) in &test.expected_registers {
            let actual = tracer.trace(&bytes, 0x400000)
                .ok()
                .and_then(|_| {
                    // Get last step register
                    steps.last().and_then(|last_step| {
                        last_step.reg_diffs.iter().find(|d| d.reg.eq_ignore_ascii_case(exp_reg)).map(|d| d.after)
                    })
                })
                .unwrap_or(0);

            if actual != exp_val {
                mismatches.push(format!(
                    "Register '{}' expected 0x{:x} ({}), got 0x{:x} ({})",
                    exp_reg, exp_val, exp_val, actual, actual
                ));
            }
        }

        let passed = mismatches.is_empty();
        if passed {
            passed_count += 1;
        }

        results.push(TestResult {
            name: test.name.clone(),
            passed,
            steps_executed: steps.len(),
            mismatches,
        });
    }

    Ok(VerificationReport {
        total_tests: tests.len(),
        passed_tests: passed_count,
        failed_tests: tests.len() - passed_count,
        results,
    })
}
