/**
 * @file mqtt_client_test.c
 * @brief KUnit tests for the MQTT Client Kernel Module
 *
 * This module contains unit tests for the MQTT client kernel module,
 * focusing on the initialization and cleanup routines.
 */

#include <kunit/test.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <kunit/assert.h>

/* Declare the external symbols from the MQTT client module */
extern int mqtt_client_init(void);
extern void mqtt_client_exit(void);
extern struct task_struct *client_thread_st;

/**
 * @brief Test the initialization function of the MQTT client module.
 *
 * This test checks if the MQTT client module initializes correctly
 * and the client thread is created successfully.
 */
static void mqtt_client_init_test(struct kunit *test)
{
    int ret;

    /* Call the initialization function */
    ret = mqtt_client_init();

    /* Verify that initialization was successful */
    KUNIT_EXPECT_EQ(test, ret, 0);
    KUNIT_ASSERT_NOT_NULL(test, client_thread_st);
    KUNIT_EXPECT_FALSE(test, IS_ERR(client_thread_st));
}

/**
 * @brief Test the exit function of the MQTT client module.
 *
 * This test checks if the MQTT client module exits cleanly
 * and the client thread is stopped properly.
 */
static void mqtt_client_exit_test(struct kunit *test)
{
    /* Ensure the client thread is running */
    KUNIT_ASSERT_NOT_NULL(test, client_thread_st);

    /* Call the exit function */
    mqtt_client_exit();

    /* Verify that the client thread has been stopped */
    KUNIT_EXPECT_NULL(test, client_thread_st);
}

/* Define the test cases */
static struct kunit_case mqtt_client_test_cases[] = {
    KUNIT_CASE(mqtt_client_init_test),
    KUNIT_CASE(mqtt_client_exit_test),
    {}
};

/* Define the test suite */
static struct kunit_suite mqtt_client_test_suite = {
    .name = "mqtt_client_test",
    .test_cases = mqtt_client_test_cases,
};

/* Register the test suite */
kunit_test_suite(mqtt_client_test_suite);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pawel Ratanczuk");
MODULE_DESCRIPTION("KUnit Tests for Simple MQTT Client Kernel Module");
