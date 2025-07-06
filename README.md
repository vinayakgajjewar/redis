# Redis from scratch

A toy re-implementation of the Redis key-value store.

```
cmake --build cmake-build-debug --target server -j 10
cmake --build cmake-build-debug --target client -j 10
cmake-build-debug/server
```

In a separate terminal:

```
cmake-build-debug/client
```