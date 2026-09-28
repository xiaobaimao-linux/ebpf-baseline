#!/bin/bash
FILE_COUNT=10000
TEST_DIR=/tmp/fim_bench
mkdir -p $TEST_DIR

echo "=== 1. 创建文件 ==="
start=$(date +%s%N)
for i in $(seq 1 $FILE_COUNT); do
    echo "test_$i" > $TEST_DIR/file_$i
done
end=$(date +%s%N)
echo "创建 $FILE_COUNT 个文件，耗时 $(( (end-start)/1000000 ))ms，吞吐量: $(( FILE_COUNT * 1000000000 / (end-start) )) ops/s"

echo "=== 2. 批量写文件 ==="
start=$(date +%s%N)
for i in $(seq 1 $FILE_COUNT); do
    echo "update_$i" >> $TEST_DIR/file_$i
done
end=$(date +%s%N)
echo "批量写，耗时 $(( (end-start)/1000000 ))ms，吞吐量: $(( FILE_COUNT * 1000000000 / (end-start) )) ops/s"

echo "=== 3. 批量 chmod ==="
start=$(date +%s%N)
for i in $(seq 1 $FILE_COUNT); do
    chmod 644 $TEST_DIR/file_$i
done
end=$(date +%s%N)
echo "批量chmod，耗时 $(( (end-start)/1000000 ))ms，吞吐量: $(( FILE_COUNT * 1000000000 / (end-start) )) ops/s"

echo "=== 4. 批量重命名 ==="
start=$(date +%s%N)
for i in $(seq 1 $FILE_COUNT); do
    mv $TEST_DIR/file_$i $TEST_DIR/file_$i.new
done
end=$(date +%s%N)
echo "批量重命名，耗时 $(( (end-start)/1000000 ))ms，吞吐量: $(( FILE_COUNT * 1000000000 / (end-start) )) ops/s"

echo "=== 5. 批量删除 ==="
start=$(date +%s%N)
for i in $(seq 1 $FILE_COUNT); do
    rm $TEST_DIR/file_$i.new
done
end=$(date +%s%N)
echo "批量删除，耗时 $(( (end-start)/1000000 ))ms，吞吐量: $(( FILE_COUNT * 1000000000 / (end-start) )) ops/s"

rm -rf $TEST_DIR
