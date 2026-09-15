pub fn generate_c_harness(func_name: &str, ret_type: &str, arg_types: &[&str], test_args: &[&[&str]]) -> String {
    let mut s = String::new();
    s.push_str("#include <stdio.h>\n#include <stdint.h>\n#include <assert.h>\n\n");
    s.push_str(&format!("extern {} {}({});\n\n", ret_type, func_name, arg_types.join(", ")));
    s.push_str("int main(void) {\n");
    s.push_str(&format!("    printf(\"Running tests for assembly function '{}'...\\n\");\n\n", func_name));

    for (i, args) in test_args.iter().enumerate() {
        s.push_str(&format!("    // Test case {}\n", i + 1));
        s.push_str(&format!("    {} res{} = {}({});\n", ret_type, i + 1, func_name, args.join(", ")));
        s.push_str(&format!("    printf(\"Test {} result: %lu\\n\", (uint64_t)res{});\n\n", i + 1, i + 1));
    }

    s.push_str("    printf(\"All tests completed successfully!\\n\");\n");
    s.push_str("    return 0;\n}\n");
    s
}

pub fn generate_python_ctypes_harness(lib_name: &str, func_name: &str) -> String {
    format!(
r#"import ctypes
import os
import sys

def run_tests():
    lib_path = os.path.abspath("{lib_name}")
    print(f"Loading assembly shared library: {{lib_path}}")
    try:
        asm_lib = ctypes.CDLL(lib_path)
    except Exception as e:
        print(f"Failed to load shared library: {{e}}")
        sys.exit(1)

    func = getattr(asm_lib, "{func_name}")
    func.restype = ctypes.c_uint64
    func.argtypes = [ctypes.c_uint64, ctypes.c_uint64]

    print(f"Calling assembly function '{func_name}'...")
    res = func(10, 20)
    print(f"Result: {{res}}")

if __name__ == "__main__":
    run_tests()
"#
    )
}
