/*
    Tests for sdap_save_group() bypass path equivalence.

    Copyright (C) 2026 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.
*/

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <stdlib.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_sdap.h"
#include "util/util_sss_idmap.h"

#include "providers/ad/ad_opts.c"
#include "providers/ldap/sdap_async_groups.c"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sdap_save_group_conf.ldb"
#define TEST_ID_PROVIDER "ldap"
#define TEST_DOM_NAME "test.domain"
#define TEST_BASE_DN "dc=test,dc=domain,cn=sysdb"

#define TEST_USER_BASE 30000
#define TEST_GROUP_GID 50000
#define TEST_NUM_MEMBERS 100

struct test_sdap_save_group_ctx {
    struct sss_test_ctx *tctx;
    struct sdap_options *opts;
};

static int test_sdap_save_group_setup(void **state)
{
    struct test_sdap_save_group_ctx *test_ctx;
    struct sss_test_conf_param params[] = {
        { "ldap_schema", "rfc2307bis" },
        { "ldap_search_base", TEST_BASE_DN },
        { "ldap_user_search_base", "cn=users," TEST_BASE_DN },
        { "ldap_group_search_base", "cn=groups," TEST_BASE_DN },
        { "ldap_id_mapping", "false" },
        { NULL, NULL },
    };
    int ret;
    int i;

    /* Clean stale DB from previous runs */
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", TESTS_PATH);
        system(cmd);
    }
    test_dom_suite_setup(TESTS_PATH);

    test_ctx = talloc_zero(global_talloc_context,
                           struct test_sdap_save_group_ctx);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                          TEST_CONF_DB, TEST_DOM_NAME,
                                          TEST_ID_PROVIDER, params);
    assert_non_null(test_ctx->tctx);

    test_ctx->opts = mock_sdap_options_ldap(test_ctx,
                                             test_ctx->tctx->dom,
                                             test_ctx->tctx->confdb,
                                             test_ctx->tctx->conf_dom_path);
    assert_non_null(test_ctx->opts);

    /* Initialize idmap_ctx to avoid NULL deref in sdap_save_group.
     * sdap_idmap_domain_has_algorithmic_mapping dereferences
     * ctx->id_ctx->opts->basic and ctx->id_ctx->be->provider.
     */
    {
        struct sdap_idmap_ctx *idmap_ctx;
        struct sdap_id_ctx *id_ctx;
        enum idmap_error_code err;

        idmap_ctx = talloc_zero(test_ctx->opts, struct sdap_idmap_ctx);
        assert_non_null(idmap_ctx);

        err = sss_idmap_init(sss_idmap_talloc, idmap_ctx,
                             sss_idmap_talloc_free,
                             &idmap_ctx->map);
        assert_int_equal(err, IDMAP_SUCCESS);

        id_ctx = talloc_zero(idmap_ctx, struct sdap_id_ctx);
        assert_non_null(id_ctx);
        id_ctx->opts = test_ctx->opts;
        /* be_ctx is not available in test context; id_mapping is
         * false so dp_target_enabled is never reached (short-circuit &&) */
        id_ctx->be = NULL;
        idmap_ctx->id_ctx = id_ctx;

        test_ctx->opts->idmap_ctx = idmap_ctx;
    }

    /* Create test users */
    for (i = 0; i < TEST_NUM_MEMBERS; i++) {
        char *name;

        name = talloc_asprintf(test_ctx, "testuser%d@%s",
                               TEST_USER_BASE + i, TEST_DOM_NAME);
        assert_non_null(name);

        ret = sysdb_store_user(test_ctx->tctx->dom, name, NULL,
                               TEST_USER_BASE + i, 0, "Test User",
                               "/home/test", "/bin/bash",
                               NULL, NULL, NULL, -1, 0);
        assert_int_equal(ret, EOK);
        talloc_free(name);
    }

    *state = test_ctx;
    return 0;
}

static int test_sdap_save_group_teardown(void **state)
{
    struct test_sdap_save_group_ctx *test_ctx;

    test_ctx = talloc_get_type(*state,
                               struct test_sdap_save_group_ctx);
    talloc_free(test_ctx);
    return 0;
}

static struct sysdb_attrs *build_mock_group_attrs(
    TALLOC_CTX *mem_ctx,
    struct test_sdap_save_group_ctx *test_ctx,
    int num_members,
    int num_ghosts)
{
    struct sysdb_attrs *attrs;
    char *dn;
    int i;
    int ret;

    attrs = sysdb_new_attrs(mem_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, "objectClass", "posixGroup");
    assert_int_equal(ret, EOK);

    dn = talloc_asprintf(attrs,
                         "name=testgroup%d@%s,cn=groups,%s",
                         TEST_GROUP_GID, TEST_DOM_NAME, TEST_BASE_DN);
    assert_non_null(dn);
    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, dn);
    assert_int_equal(ret, EOK);

    {
        const char *shortname;
        shortname = talloc_asprintf(attrs, "testgroup%d", TEST_GROUP_GID);
        assert_non_null(shortname);

        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, shortname);
        assert_int_equal(ret, EOK);

        ret = sysdb_attrs_add_string(attrs, "cn", shortname);
    }
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_uint32(attrs, "gidNumber", TEST_GROUP_GID);
    assert_int_equal(ret, EOK);

    /* Add member DNs using sysdb DN format */
    for (i = 0; i < num_members; i++) {
        char *username;
        char *member_dn;
        username = talloc_asprintf(attrs, "testuser%d@%s",
                                   TEST_USER_BASE + i, TEST_DOM_NAME);
        assert_non_null(username);
        member_dn = sysdb_user_strdn(attrs,
                                     test_ctx->tctx->dom->name,
                                     username);
        assert_non_null(member_dn);
        ret = sysdb_attrs_add_string(attrs,
                test_ctx->opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                member_dn);
        assert_int_equal(ret, EOK);
    }

    /* Add ghosts */
    for (i = 0; i < num_ghosts; i++) {
        char *ghost;
        ghost = talloc_asprintf(attrs, "ghost%d@%s", i, TEST_DOM_NAME);
        assert_non_null(ghost);
        ret = sysdb_attrs_add_string(attrs, SYSDB_GHOST, ghost);
        assert_int_equal(ret, EOK);
    }

    return attrs;
}

static void snapshot_user(struct sss_domain_info *dom,
                          uid_t uid,
                          struct ldb_message **out)
{
    const char *all[] = { "*", NULL };
    int ret;

    ret = sysdb_search_user_by_uid(dom, dom, uid, all, out);
    assert_int_equal(ret, EOK);
}

static void snapshot_group(struct sss_domain_info *dom,
                           gid_t gid,
                           struct ldb_message **out)
{
    const char *all[] = { "*", NULL };
    int ret;

    ret = sysdb_search_group_by_gid(dom, dom, gid, all, out);
    assert_int_equal(ret, EOK);
}

static void assert_memberof_equal(struct ldb_message *a,
                                  struct ldb_message *b,
                                  int user_idx)
{
    const struct ldb_message_element *el_a;
    const struct ldb_message_element *el_b;
    int i;

    el_a = ldb_msg_find_element(a, SYSDB_MEMBEROF);
    el_b = ldb_msg_find_element(b, SYSDB_MEMBEROF);

    assert_non_null(el_a);
    assert_non_null(el_b);
    assert_int_equal(el_a->num_values, el_b->num_values);

    for (i = 0; i < el_a->num_values; i++) {
        assert_non_null(ldb_msg_find_val(el_b, &el_a->values[i]));
    }
}

/* Test 1: equivalence between module path and bypass path */
static void test_sdap_save_group_bypass_equivalence(void **state)
{
    struct test_sdap_save_group_ctx *test_ctx;
    struct sysdb_attrs *attrs;
    struct ldb_message *mod_users[3];
    struct ldb_message *mod_group;
    struct ldb_message *byp_users[3];
    struct ldb_message *byp_group;
    const struct ldb_message_element *mod_uid_el;
    const struct ldb_message_element *byp_uid_el;
    const struct ldb_message_element *mod_ghost_el;
    const struct ldb_message_element *byp_ghost_el;
    int spot[] = { TEST_USER_BASE, TEST_USER_BASE + 49,
                   TEST_USER_BASE + 99 };
    int ret;
    int i;

    test_ctx = talloc_get_type(*state,
                               struct test_sdap_save_group_ctx);

    /* Path A: store via module path using sysdb_store_group directly */
    {
        struct sysdb_attrs *grp_attrs;
        char *groupname;
        char *username;
        char *member;

        groupname = talloc_asprintf(test_ctx, "testgroup%d@%s",
                                    TEST_GROUP_GID, TEST_DOM_NAME);
        assert_non_null(groupname);

        grp_attrs = sysdb_new_attrs(test_ctx);
        assert_non_null(grp_attrs);

        for (i = 0; i < TEST_NUM_MEMBERS; i++) {
            username = talloc_asprintf(grp_attrs, "testuser%d@%s",
                                       TEST_USER_BASE + i, TEST_DOM_NAME);
            assert_non_null(username);
            member = sysdb_user_strdn(grp_attrs,
                                      test_ctx->tctx->dom->name, username);
            assert_non_null(member);
            ret = sysdb_attrs_steal_string(grp_attrs, SYSDB_MEMBER, member);
            assert_int_equal(ret, EOK);
        }
        ret = sysdb_attrs_add_string(grp_attrs, SYSDB_GHOST,
                                     "ghost0@" TEST_DOM_NAME);
        assert_int_equal(ret, EOK);
        ret = sysdb_attrs_add_string(grp_attrs, SYSDB_GHOST,
                                     "ghost1@" TEST_DOM_NAME);
        assert_int_equal(ret, EOK);

        ret = sysdb_store_group(test_ctx->tctx->dom, groupname,
                                TEST_GROUP_GID, grp_attrs,
                                -1, time(NULL));
        assert_int_equal(ret, EOK);
    }

    for (i = 0; i < 3; i++) {
        snapshot_user(test_ctx->tctx->dom, spot[i], &mod_users[i]);
    }
    snapshot_group(test_ctx->tctx->dom, TEST_GROUP_GID, &mod_group);

    ret = sysdb_delete_group(test_ctx->tctx->dom, NULL, TEST_GROUP_GID);
    assert_int_equal(ret, EOK);

    /* Path B: bypass path via sdap_save_group */
    setenv("SSSD_SDAP_BYPASS_THRESHOLD", "0", 1);

    attrs = build_mock_group_attrs(test_ctx, test_ctx,
                                   TEST_NUM_MEMBERS, 2);
    ret = sdap_save_group(test_ctx, test_ctx->opts,
                          test_ctx->tctx->dom, attrs,
                          true, true, NULL, NULL, time(NULL));
    assert_int_equal(ret, EOK);

    for (i = 0; i < 3; i++) {
        snapshot_user(test_ctx->tctx->dom, spot[i], &byp_users[i]);
    }
    snapshot_group(test_ctx->tctx->dom, TEST_GROUP_GID, &byp_group);

    /* Compare memberOf on sampled users */
    for (i = 0; i < 3; i++) {
        assert_memberof_equal(mod_users[i], byp_users[i], spot[i]);
    }

    /* Compare memberuid */
    mod_uid_el = ldb_msg_find_element(mod_group, SYSDB_MEMBERUID);
    byp_uid_el = ldb_msg_find_element(byp_group, SYSDB_MEMBERUID);
    assert_non_null(mod_uid_el);
    assert_non_null(byp_uid_el);
    assert_int_equal(mod_uid_el->num_values, byp_uid_el->num_values);

    /* Compare ghost */
    mod_ghost_el = ldb_msg_find_element(mod_group, SYSDB_GHOST);
    byp_ghost_el = ldb_msg_find_element(byp_group, SYSDB_GHOST);
    if (mod_ghost_el != NULL) {
        assert_non_null(byp_ghost_el);
        assert_int_equal(mod_ghost_el->num_values,
                         byp_ghost_el->num_values);
        for (i = 0; i < mod_ghost_el->num_values; i++) {
            assert_non_null(ldb_msg_find_val(byp_ghost_el,
                                             &mod_ghost_el->values[i]));
        }
    }

    unsetenv("SSSD_SDAP_BYPASS_THRESHOLD");
}

/* Test 2: edge cases with bypass forced for all sizes */
static void test_sdap_save_group_bypass_edge_cases(void **state)
{
    struct test_sdap_save_group_ctx *test_ctx;
    struct sysdb_attrs *attrs;
    struct ldb_message *msg;
    const struct ldb_message_element *el;
    int ret;

    test_ctx = talloc_get_type(*state,
                               struct test_sdap_save_group_ctx);
    setenv("SSSD_SDAP_BYPASS_THRESHOLD", "0", 1);

    /* Case 1: 0 members, 0 ghosts */
    attrs = build_mock_group_attrs(test_ctx, test_ctx, 0, 0);
    ret = sdap_save_group(test_ctx, test_ctx->opts,
                          test_ctx->tctx->dom, attrs,
                          true, true, NULL, NULL, time(NULL));
    assert_int_equal(ret, EOK);

    snapshot_group(test_ctx->tctx->dom, TEST_GROUP_GID, &msg);
    el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
    assert_true(el == NULL || el->num_values == 0);

    ret = sysdb_delete_group(test_ctx->tctx->dom, NULL, TEST_GROUP_GID);
    assert_int_equal(ret, EOK);

    /* Case 2: 1 member, 0 ghosts */
    attrs = build_mock_group_attrs(test_ctx, test_ctx, 1, 0);
    ret = sdap_save_group(test_ctx, test_ctx->opts,
                          test_ctx->tctx->dom, attrs,
                          true, true, NULL, NULL, time(NULL));
    assert_int_equal(ret, EOK);

    snapshot_group(test_ctx->tctx->dom, TEST_GROUP_GID, &msg);
    el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
    assert_non_null(el);
    assert_int_equal(el->num_values, 1);

    {
        struct ldb_message *umsg;
        snapshot_user(test_ctx->tctx->dom, TEST_USER_BASE, &umsg);
        el = ldb_msg_find_element(umsg, SYSDB_MEMBEROF);
        assert_non_null(el);
    }

    ret = sysdb_delete_group(test_ctx->tctx->dom, NULL, TEST_GROUP_GID);
    assert_int_equal(ret, EOK);

    /* Case 3: 0 members, 1 ghost */
    attrs = build_mock_group_attrs(test_ctx, test_ctx, 0, 1);
    ret = sdap_save_group(test_ctx, test_ctx->opts,
                          test_ctx->tctx->dom, attrs,
                          true, true, NULL, NULL, time(NULL));
    assert_int_equal(ret, EOK);

    snapshot_group(test_ctx->tctx->dom, TEST_GROUP_GID, &msg);
    el = ldb_msg_find_element(msg, SYSDB_GHOST);
    assert_non_null(el);
    assert_int_equal(el->num_values, 1);

    el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
    assert_true(el == NULL || el->num_values == 0);

    unsetenv("SSSD_SDAP_BYPASS_THRESHOLD");
}

/* Test 3: idempotency */
static void test_sdap_save_group_bypass_idempotent(void **state)
{
    struct test_sdap_save_group_ctx *test_ctx;
    struct sysdb_attrs *attrs;
    struct ldb_message *msg;
    const struct ldb_message_element *el;
    int ret;

    test_ctx = talloc_get_type(*state,
                               struct test_sdap_save_group_ctx);
    setenv("SSSD_SDAP_BYPASS_THRESHOLD", "0", 1);

    attrs = build_mock_group_attrs(test_ctx, test_ctx, 10, 1);
    ret = sdap_save_group(test_ctx, test_ctx->opts,
                          test_ctx->tctx->dom, attrs,
                          true, true, NULL, NULL, time(NULL));
    assert_int_equal(ret, EOK);

    /* Call again with same data */
    attrs = build_mock_group_attrs(test_ctx, test_ctx, 10, 1);
    ret = sdap_save_group(test_ctx, test_ctx->opts,
                          test_ctx->tctx->dom, attrs,
                          true, true, NULL, NULL, time(NULL));
    assert_int_equal(ret, EOK);

    /* Verify no duplicates */
    {
        struct ldb_message *umsg;
        snapshot_user(test_ctx->tctx->dom, TEST_USER_BASE, &umsg);
        el = ldb_msg_find_element(umsg, SYSDB_MEMBEROF);
        assert_non_null(el);
        assert_int_equal(el->num_values, 1);
    }

    snapshot_group(test_ctx->tctx->dom, TEST_GROUP_GID, &msg);
    el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
    assert_non_null(el);
    assert_int_equal(el->num_values, 10);

    el = ldb_msg_find_element(msg, SYSDB_GHOST);
    assert_non_null(el);
    assert_int_equal(el->num_values, 1);

    unsetenv("SSSD_SDAP_BYPASS_THRESHOLD");
}

int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_sdap_save_group_bypass_equivalence,
            test_sdap_save_group_setup,
            test_sdap_save_group_teardown),
        cmocka_unit_test_setup_teardown(
            test_sdap_save_group_bypass_edge_cases,
            test_sdap_save_group_setup,
            test_sdap_save_group_teardown),
        cmocka_unit_test_setup_teardown(
            test_sdap_save_group_bypass_idempotent,
            test_sdap_save_group_setup,
            test_sdap_save_group_teardown),
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
