# ssl证书生成工具

主要用于生成自签名证书

```shell
# 生成CA根证书和ssl证书
cert_tool make-ca --cert-path my_root_ca.cer --key-path my_root_ca_key.pem -Y 15
cert_tool make-cert --cert-path local.cer --key-path local_key.pem --ca-cert-path my_root_ca.cer --ca-key-path my_root_ca_key.pem --ip 127.0.0.1 --ip 192.168.1.1 --domain localhost -Y 1
```

多级授权结构

CA根证书  >   CA中间证书 > ssl证书

```shell
cert_tool make-ca --cert-path my_root_ca.cer --key-path my_root_ca_key.pem -Y 15
cert_tool make-ca --cert-path ca.cer --key-path ca_key.pem --parent-cert-path my_root_ca.cer --parent-key-path my_root_ca_key.pem -N "liuguang v2 CA" --max-path 0 -Y 10
# 使用中间证书签署
cert_tool make-cert --cert-path local.cer --key-path local_key.pem --ca-cert-path ca.cer --ca-key-path ca_key.pem --ip 127.0.0.1 --ip 192.168.1.1 --domain localhost -Y 1
```

