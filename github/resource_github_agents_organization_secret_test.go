package github

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAgentsOrganizationSecretRotation(t *testing.T) {
	t.Parallel()
	ids := []int64{123, 456}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/test/agents/secrets/TEST/repositories" {
			repositories := []map[string]int64{}
			for _, id := range ids {
				repositories = append(repositories, map[string]int64{"id": id})
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"repositories": repositories}); err != nil {
				t.Error(err)
			}
			return
		}
		if r.URL.Path != "/orgs/test/agents/secrets/TEST" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method == http.MethodPut {
			var body struct {
				IDs []int64 `json:"selected_repository_ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			// GitHub replaces access with an empty list when the field is omitted.
			ids = body.IDs
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if _, err := fmt.Fprint(w, `{"name":"TEST","visibility":"selected","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}`); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	meta := &Owner{name: "test", IsOrganization: true, maxPerPage: 100, v3client: mustCreateTestGitHubClient(t, server.URL)}
	d := schema.TestResourceDataRaw(t, resourceGithubAgentsOrganizationSecret().Schema, map[string]any{"secret_name": "TEST", "visibility": "selected", "value_encrypted": "c2VjcmV0", "key_id": "key"})
	d.SetId("TEST")
	if diagnostics := resourceGithubAgentsOrganizationSecretUpdate(t.Context(), d, meta); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	observedIDs, _ := d.Get("selected_repository_ids").(*schema.Set)
	if !observedIDs.Equal(schema.NewSet(schema.HashInt, []any{123, 456})) {
		t.Fatal("rotation removed live repository access not present in Terraform state")
	}
	baseline := d.Get("updated_at")
	if err := d.Set("updated_at", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if diagnostics := resourceGithubAgentsOrganizationSecretRead(t.Context(), d, meta); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	if d.Get("updated_at") == baseline || d.Get("remote_updated_at") != baseline {
		t.Fatal("refresh lost the provider timestamp baseline")
	}
}

func TestAgentsOrganizationSecretAccessDrift(t *testing.T) {
	t.Parallel()
	for _, ids := range [][]int{{123}, {}} {
		t.Run(fmt.Sprint(ids), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/repositories") {
					repositories := []map[string]int{}
					for _, id := range ids {
						repositories = append(repositories, map[string]int{"id": id})
					}
					if err := json.NewEncoder(w).Encode(map[string]any{"repositories": repositories}); err != nil {
						t.Error(err)
					}
					return
				}
				if _, err := fmt.Fprint(w, `{"name":"TEST","visibility":"selected","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}`); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			meta := &Owner{name: "test", IsOrganization: true, maxPerPage: 100, v3client: mustCreateTestGitHubClient(t, server.URL)}
			previousIDs := []any{}
			if len(ids) == 0 {
				previousIDs = append(previousIDs, 123)
			}
			d := schema.TestResourceDataRaw(t, resourceGithubAgentsOrganizationSecret().Schema, map[string]any{
				"secret_name": "TEST", "visibility": "selected", "value": "placeholder",
				"updated_at": "2026-01-01 00:00:00 +0000 UTC", "selected_repository_ids": previousIDs,
			})
			d.SetId("TEST")
			if diagnostics := resourceGithubAgentsOrganizationSecretRead(t.Context(), d, meta); diagnostics.HasError() {
				t.Fatal(diagnostics)
			}
			if d.Get("updated_at") != d.Get("remote_updated_at") {
				t.Fatal("repository access change was mistaken for secret value drift")
			}
			// Once access is unchanged, a later timestamp must still detect value drift.
			if err := d.Set("updated_at", "2026-01-01 00:00:00 +0000 UTC"); err != nil {
				t.Fatal(err)
			}
			if diagnostics := resourceGithubAgentsOrganizationSecretRead(t.Context(), d, meta); diagnostics.HasError() {
				t.Fatal(diagnostics)
			}
			if d.Get("updated_at") == d.Get("remote_updated_at") {
				t.Fatal("value drift with unchanged access was ignored")
			}
		})
	}
}

func TestAgentsOrganizationSecretRotationAccessError(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			t.Error("rotation must not proceed when repository access cannot be read")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/repositories") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if _, err := fmt.Fprint(w, `{"name":"TEST","visibility":"selected"}`); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	meta := &Owner{name: "test", IsOrganization: true, maxPerPage: 100, v3client: mustCreateTestGitHubClient(t, server.URL)}
	d := schema.TestResourceDataRaw(t, resourceGithubAgentsOrganizationSecret().Schema, map[string]any{"secret_name": "TEST", "visibility": "selected", "value_encrypted": "c2VjcmV0", "key_id": "key"})
	d.SetId("TEST")
	if diagnostics := resourceGithubAgentsOrganizationSecretUpdate(t.Context(), d, meta); !diagnostics.HasError() {
		t.Fatal("rotation ignored repository access lookup failure")
	}
}

func TestAccGithubAgentsOrganizationSecret(t *testing.T) {
	t.Parallel()

	skipUnlessHasOrgs(t)

	t.Run("with_value", func(t *testing.T) {
		t.Parallel()

		key := mustGetOrganizationAgentsPublicKey(t)

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "%%s"
  visibility  = "all"
}

data "github_agents_organization_public_key" "test" {}

data "github_agents_organization_secrets" "test" {
  depends_on = [github_agents_organization_secret.test]
}

output "test_secret_metadata" {
  value = [for secret in data.github_agents_organization_secrets.test.secrets : secret if secret.name == github_agents_organization_secret.test.secret_name]
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(config, "super_secret_value"),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue("github_agents_organization_secret.test", tfjsonpath.New("key_id"), knownvalue.StringExact(key.GetKeyID())),
						statecheck.ExpectKnownValue("github_agents_organization_secret.test", tfjsonpath.New("created_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_organization_secret.test", tfjsonpath.New("updated_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_organization_secret.test", tfjsonpath.New("remote_updated_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("data.github_agents_organization_public_key.test", tfjsonpath.New("key"), knownvalue.StringExact(key.GetKey())),
						statecheck.ExpectKnownOutputValue("test_secret_metadata", knownvalue.ListExact([]knownvalue.Check{
							knownvalue.MapExact(map[string]knownvalue.Check{
								"name":       knownvalue.StringExact(secretName),
								"visibility": knownvalue.StringExact("all"),
								"created_at": knownvalue.NotNull(),
								"updated_at": knownvalue.NotNull(),
							}),
						})),
					},
				},
				{
					Config: fmt.Sprintf(config, "super_secret_value_2"),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
				{
					ResourceName:            "github_agents_organization_secret.test",
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: []string{"key_id", "value"},
				},
			},
		})
	})

	t.Run("with_value_encrypted", func(t *testing.T) {
		t.Parallel()

		key := mustGetOrganizationAgentsPublicKey(t)

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name     = "%s"
  key_id          = "%s"
  value_encrypted = "%%s"
  visibility      = "all"
}
`, secretName, key.GetKeyID())

		encrypt := func(value string) string {
			encryptedBytes, err := encryptPlaintext(value, key.GetKey())
			if err != nil {
				t.Fatalf("failed to encrypt plaintext: %v", err)
			}
			return base64.StdEncoding.EncodeToString(encryptedBytes)
		}

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(config, encrypt("super_secret_value")),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue("github_agents_organization_secret.test", tfjsonpath.New("created_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_organization_secret.test", tfjsonpath.New("updated_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_organization_secret.test", tfjsonpath.New("remote_updated_at"), knownvalue.NotNull()),
					},
				},
				{
					Config: fmt.Sprintf(config, encrypt("super_secret_value_2")),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
				{
					ResourceName:            "github_agents_organization_secret.test",
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: []string{"key_id", "value_encrypted"},
				},
			},
		})
	})

	t.Run("with_visibility_all", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "all"
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
			},
		})
	})

	t.Run("with_visibility_private", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "private"
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
			},
		})
	})

	t.Run("with_visibility_selected", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "selected"
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
			},
		})
	})

	t.Run("can_change_visibility", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "%%v"
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(config, "all"),
				},
				{
					Config: fmt.Sprintf(config, "private"),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
				{
					Config: fmt.Sprintf(config, "selected"),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
			},
		})
	})

	t.Run("updates_on_drift", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "all"
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
				{
					PreConfig: func() {
						// GitHub records a secret's updated_at to the second. Wait one second so that
						// this write gets a later updated_at than the one in state, or the provider
						// can't see the change.
						time.Sleep(time.Second)
						mustUpdateOrganizationAgentsSecret(t, secretName, "super_secret_value_2")
					},
					Config: config,
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
			},
		})
	})

	t.Run("updates_on_drift_with_visibility_selected", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "selected"
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
				{
					PreConfig: func() {
						// GitHub records a secret's updated_at to the second. Wait one second so that
						// this write gets a later updated_at than the one in state, or the provider
						// can't see the change.
						time.Sleep(time.Second)
						mustUpdateOrganizationAgentsSecret(t, secretName, "super_secret_value_2")
					},
					Config: config,
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
			},
		})
	})

	t.Run("lifecycle_ignore_suppresses_drift", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "all"

  lifecycle {
    ignore_changes = [updated_at]
  }
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
				{
					PreConfig: func() {
						// GitHub records a secret's updated_at to the second. Wait one second so that
						// this write gets a later updated_at than the one in state, or the provider
						// can't see the change.
						time.Sleep(time.Second)
						mustUpdateOrganizationAgentsSecret(t, secretName, "super_secret_value_2")
					},
					Config: config,
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionNoop),
						},
					},
				},
			},
		})
	})

	t.Run("recreates_when_deleted_externally", func(t *testing.T) {
		t.Parallel()

		randomID := acctest.RandString(testRandomIDLength)
		secretName := strings.ToUpper(fmt.Sprintf("%s%s", strings.ReplaceAll(testResourcePrefix, "-", "_"), randomID))

		config := fmt.Sprintf(`
resource "github_agents_organization_secret" "test" {
  secret_name = "%s"
  value       = "super_secret_value"
  visibility  = "all"
}
`, secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
				{
					PreConfig: func() {
						if _, err := testAccConf.meta.v3client.Agents.DeleteOrgSecret(t.Context(), testAccConf.meta.name, secretName); err != nil {
							t.Fatalf("failed to delete test organization agents secret: %v", err)
						}
					},
					Config: config,
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_organization_secret.test", plancheck.ResourceActionCreate),
						},
					},
				},
			},
		})
	})
}
