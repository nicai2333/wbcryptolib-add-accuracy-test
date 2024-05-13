#!/bin/bash
# 生成class文件
# 需要指出第三方jar包的路径
javac -cp jna-5.10.0.jar -d bin src/ayssl/*.java src/ayssl/test/*.java

# 解释执行class文件
# 第一个路径: . 表示so库的路径
# 第二个路径：jna-5.10.0.jar 表示所使用第三方jar包的路径
# 第三个路径：bin表示本地生成的class路径
java -cp ../build/out:jna-5.10.0.jar:./bin ayssl.test.Main