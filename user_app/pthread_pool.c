#include "pthread_pool.h"

// 线程池的入口函数，负责从任务队列中取出任务并执行
static void* thread_func(void* arg) {
    POOL* pool = (POOL*)arg;
    while(1) {
        pthread_mutex_lock(&pool->mutex);
        while(pool->task_queue_head == pool->task_queue_tail) { // 任务队列为空，等待任务
            pthread_cond_wait(&pool->busy, &pool->mutex);
        }

        TASK task = pool->task_queue[pool->task_queue_head];
        pool->task_queue_head = (pool->task_queue_head + 1) % TASK_QUEUE_LEN;
        pthread_cond_signal(&pool->free); // 唤醒等待在条件变量上的线程
        
        pthread_mutex_unlock(&pool->mutex);
        task.func(task.arg);
    }
    return NULL;
}

// 初始化线程池，即创建好若干个线程
void init_pool(POOL* pool) {
    int i = 0;
    pool->task_queue_head = 0;
    pool->task_queue_tail = 0;
    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->free, NULL);
    pthread_cond_init(&pool->busy, NULL);
    for(i = 0; i < MAX_THREAD_NUM; i++) {
        pthread_create(&pool->threads[i], NULL, thread_func, (void*)pool);
    }
}

// 向任务队列中添加任务
void execute_task(POOL* pool, void (*function)(void*), void *argument) {
    TASK task = {
        .func = function,
        .arg = argument
    };

    pthread_mutex_lock(&pool->mutex);
    // 如果任务队列满了，则等待条件变量 free 来通知有空闲的位置
    while(pool->task_queue_head == (pool->task_queue_tail + 1) % TASK_QUEUE_LEN) {
        pthread_cond_wait(&pool->free, &pool->mutex);
    }

    pool->task_queue[pool->task_queue_tail] = task;
    pool->task_queue_tail = (pool->task_queue_tail + 1) % TASK_QUEUE_LEN;
    pthread_cond_signal(&pool->busy); // 唤醒等待在条件变量上的线程
    pthread_mutex_unlock(&pool->mutex);
}