# ebpf\_demo

## How to build
```
make
```

## How to test
```
sudo demo 1234
```

The following command is failed because uid 1234 cannot create INET sockets. (Operation not permitted)
```
docker run -it --rm -u 1234 wbitt/network-multitool:minimal ping 8.8.8.8
```
