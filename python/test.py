import multiprocessing
import time

def worker(num):
    """工作进程的函数"""
    print("执行任务:", num)
    time.sleep(1)  # 模拟任务执行时间

if __name__ == "__main__":
    start_time = time.time()  # 记录开始时间

    # 创建进程池，最大进程数为3
    pool = multiprocessing.Pool(processes=3)

    # 向进程池提交任务
    for i in range(5):
        pool.apply_async(worker, (i,))

    # 关闭进程池，防止新任务提交
    pool.close()

    # 等待所有任务完成
    pool.join()

    end_time = time.time()  # 记录结束时间
    execution_time = end_time - start_time  # 计算执行时间

    print("所有任务已完成")
    print("执行时间:", execution_time, "秒")
