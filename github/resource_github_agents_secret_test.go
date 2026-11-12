package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"golang.org/x/crypto/nacl/box"
)

func TestAgentsSecretLifecycle(t *testing.T) {
	t.Parallel()
	publicKey, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	var updated int
	var exists bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		switch r.URL.Path {
		case "/repos/test/repository":
			if err := json.NewEncoder(w).Encode(map[string]int{"id": 123}); err != nil {
				t.Error(err)
			}
		case "/repos/test/repository/agents/secrets/public-key":
			if err := json.NewEncoder(w).Encode(map[string]string{"key_id": "key", "key": base64.StdEncoding.EncodeToString(publicKey[:])}); err != nil {
				t.Error(err)
			}
		case "/repos/test/repository/agents/secrets/TEST":
			switch r.Method {
			case http.MethodPut:
				exists = true
				updated++
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				exists = false
				w.WriteHeader(http.StatusNoContent)
			default:
				if !exists {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if err := json.NewEncoder(w).Encode(map[string]string{"name": "TEST", "created_at": "2026-01-01T00:00:00Z", "updated_at": time.Date(2026, 1, 1, 0, 0, updated, 0, time.UTC).Format(time.RFC3339)}); err != nil {
					t.Error(err)
				}
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	meta := &Owner{name: "test", v3client: mustCreateTestGitHubClient(t, server.URL)}
	config := `resource "github_agents_secret" "test" {
  repository = "repository"
  secret_name = "TEST"
  value = "initial"
}`
	rotated := strings.Replace(config, "initial", "rotated", 1)
	ignored := strings.Replace(rotated, "  value", "  lifecycle { ignore_changes = [updated_at] }\n  value", 1)
	externalWrite := func() { mutex.Lock(); updated++; mutex.Unlock() }
	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: map[string]func() (*schema.Provider, error){
			"github": func() (*schema.Provider, error) {
				provider := NewProvider("test", "none")()
				provider.ConfigureContextFunc = func(context.Context, *schema.ResourceData) (any, diag.Diagnostics) { return meta, nil }
				return provider, nil
			},
		},
		Steps: []resource.TestStep{
			{Config: config},
			{ResourceName: "github_agents_secret.test", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"value", "key_id"}},
			{Config: config, PlanOnly: true},
			{Config: rotated, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionUpdate)}}},
			{Config: rotated, PreConfig: externalWrite, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionUpdate)}}},
			{Config: ignored},
			{Config: ignored, PreConfig: externalWrite, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionNoop)}}},
		},
	})
	mutex.Lock()
	defer mutex.Unlock()
	if exists {
		t.Fatal("Terraform destroy left the agent secret behind")
	}
}

func TestAccGithubAgentsSecret(t *testing.T) {
	t.Parallel()

	skipUnauthenticated(t)

	t.Run("with_value", func(t *testing.T) {
		t.Parallel()

		repo := mustCreateTestRepository(t)
		key := mustGetRepositoryAgentsPublicKey(t, repo)

		config := fmt.Sprintf(`
resource "github_agents_secret" "test" {
  repository  = "%s"
  secret_name = "TEST"
  value       = "%%s"
}

data "github_agents_public_key" "test" {
  repository = github_agents_secret.test.repository
}

data "github_agents_secrets" "test" {
  full_name  = "%s/%s"
  depends_on = [github_agents_secret.test]
}
`, repo.GetName(), testAccConf.meta.name, repo.GetName())

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(config, "super_secret_value"),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("repository_id"), knownvalue.Int64Exact(repo.GetID())),
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("key_id"), knownvalue.StringExact(key.GetKeyID())),
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("created_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("updated_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("remote_updated_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("data.github_agents_public_key.test", tfjsonpath.New("key"), knownvalue.StringExact(key.GetKey())),
						statecheck.ExpectKnownValue("data.github_agents_secrets.test", tfjsonpath.New("secrets"), knownvalue.ListExact([]knownvalue.Check{
							knownvalue.MapExact(map[string]knownvalue.Check{
								"name":       knownvalue.StringExact("TEST"),
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
							plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
				{
					ResourceName:            "github_agents_secret.test",
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: []string{"key_id", "value"},
				},
			},
		})
	})

	t.Run("with_value_encrypted", func(t *testing.T) {
		t.Parallel()

		repo := mustCreateTestRepository(t)
		key := mustGetRepositoryAgentsPublicKey(t, repo)

		config := fmt.Sprintf(`
resource "github_agents_secret" "test" {
  repository      = "%s"
  secret_name     = "TEST"
  key_id          = "%s"
  value_encrypted = "%%s"
}
`, repo.GetName(), key.GetKeyID())

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
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("repository_id"), knownvalue.Int64Exact(repo.GetID())),
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("created_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("updated_at"), knownvalue.NotNull()),
						statecheck.ExpectKnownValue("github_agents_secret.test", tfjsonpath.New("remote_updated_at"), knownvalue.NotNull()),
					},
				},
				{
					Config: fmt.Sprintf(config, encrypt("super_secret_value_2")),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
				{
					ResourceName:            "github_agents_secret.test",
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: []string{"key_id", "value_encrypted"},
				},
			},
		})
	})

	t.Run("updates_on_drift", func(t *testing.T) {
		t.Parallel()

		repo := mustCreateTestRepository(t)
		secretName := "TEST"

		config := fmt.Sprintf(`
resource "github_agents_secret" "test" {
  repository  = "%s"
  secret_name = "%s"
  value       = "super_secret_value"
}
`, repo.GetName(), secretName)

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
						mustUpdateRepositoryAgentsSecret(t, repo, secretName, "super_secret_value_2")
					},
					Config: config,
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
			},
		})
	})

	t.Run("lifecycle_ignore_suppresses_drift", func(t *testing.T) {
		t.Parallel()

		repo := mustCreateTestRepository(t)
		secretName := "TEST"

		config := fmt.Sprintf(`
resource "github_agents_secret" "test" {
  repository  = "%s"
  secret_name = "%s"
  value       = "super_secret_value"

  lifecycle {
    ignore_changes = [updated_at]
  }
}
`, repo.GetName(), secretName)

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
						mustUpdateRepositoryAgentsSecret(t, repo, secretName, "super_secret_value_2")
					},
					Config: config,
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionNoop),
						},
					},
				},
			},
		})
	})

	t.Run("updates_renamed_repo", func(t *testing.T) {
		t.Parallel()

		repo := mustCreateTestRepository(t)
		newRepoName := fmt.Sprintf("%s-updated", repo.GetName())

		config := `
resource "github_agents_secret" "test" {
  repository  = "%s"
  secret_name = "TEST"
  value       = "super_secret_value"
}
`

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(config, repo.GetName()),
				},
				{
					PreConfig: func() {
						mustRenameTestRepository(t, repo, newRepoName)
					},
					Config: fmt.Sprintf(config, newRepoName),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionUpdate),
						},
					},
				},
			},
		})
	})

	t.Run("recreates_changed_repo", func(t *testing.T) {
		t.Parallel()

		repo := mustCreateTestRepository(t)
		repo2 := mustCreateTestRepository(t)

		config := `
resource "github_agents_secret" "test" {
  repository  = "%s"
  secret_name = "TEST"
  value       = "super_secret_value"
}
`

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(config, repo.GetName()),
				},
				{
					Config: fmt.Sprintf(config, repo2.GetName()),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionReplace),
						},
					},
				},
			},
		})
	})

	t.Run("recreates_when_deleted_externally", func(t *testing.T) {
		t.Parallel()

		repo := mustCreateTestRepository(t)
		secretName := "TEST"

		config := fmt.Sprintf(`
resource "github_agents_secret" "test" {
  repository  = "%s"
  secret_name = "%s"
  value       = "super_secret_value"
}
`, repo.GetName(), secretName)

		resource.Test(t, resource.TestCase{
			ProviderFactories: providerFactories,
			Steps: []resource.TestStep{
				{
					Config: config,
				},
				{
					PreConfig: func() {
						if _, err := testAccConf.meta.v3client.Agents.DeleteRepoSecret(t.Context(), testAccConf.meta.name, repo.GetName(), secretName); err != nil {
							t.Fatalf("failed to delete test repository agents secret: %v", err)
						}
					},
					Config: config,
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction("github_agents_secret.test", plancheck.ResourceActionCreate),
						},
					},
				},
			},
		})
	})
}
