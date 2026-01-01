The cryptographic library is divided into two components: `lib.c` (C implementation) and `lib.py` (Python interface).

This separation is designed to maximize performance, particularly for the Kyber algorithm. Kyber is an embarrassingly parallel algorithm, making it highly suitable for optimizations such as SIMD (Single Instruction, Multiple Data) and parallel processing—capabilities that are not efficiently achievable in pure Python. By implementing the core logic in C and leveraging SIMD instructions, we observed that Kyber-512 outperforms ECC (Elliptic Curve Cryptography) in terms of speed. In contrast, the Python-only implementation showed ECC as faster, highlighting the significant performance gains from native code and parallelism.

**Compiling the C Library**

To build the C library (`lib.dll`), ensure you have Visual Studio 2022 installed with C++ development tools and compute capabilities. Then, open a Developer Command Prompt and run:

	cl /LD /O2 /W3 lib.c /link /OUT:lib.dll
	cl /LD /O2 /W3 /arch:AVX2 lib.c /link /OUT:lib.dll

This command compiles `lib.c` into a dynamic link library (`lib.dll`) with optimizations enabled. Once compiled, the DLL can be used directly by the Python application via the provided interface in `lib.py`.

**Usage**

After compiling, you can start the application as usual. The Python code will automatically utilize the optimized C library for cryptographic operations, ensuring maximum performance for Kyber and other supported algorithms.