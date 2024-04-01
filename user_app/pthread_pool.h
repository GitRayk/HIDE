#include <pthread.h>

// 实现线程池，定义最大的线程数量和任务队列长度
#define MAX_THREAD_NUM 5
#define TASK_QUEUE_LEN 128


// 定义任务结构体，提供完成任务的函数和参数
typedef struct pthread_task {
    void (*func)(void*);
    void* arg;
} TASK;

// 定义线程池结构体，包含线程池的状态、任务队列、线程数组
// 任务队列使用环形缓冲区，head和tail分别指向队列的头和尾
// 线程数组用于存放线程句柄
typedef struct pthread_pool {
    int task_queue_head;
    int task_queue_tail;
    pthread_mutex_t mutex;  // 互斥锁，用于互斥访问任务队列
    pthread_cond_t free;    // 条件变量，用于确认任务队列中是否有空间添加任务
    pthread_cond_t busy;    // 条件变量，用于确认任务队列中是否有任务需要执行
    pthread_t threads[MAX_THREAD_NUM];
    TASK task_queue[TASK_QUEUE_LEN];
} POOL;

void init_pool(POOL* pool);  // 初始化线程池
void execute_task(POOL* pool, void (*function)(void*), void *argument);  // 执行任务