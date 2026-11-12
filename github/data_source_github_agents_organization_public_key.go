package github

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGithubAgentsOrganizationPublicKey() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceGithubAgentsOrganizationPublicKeyRead,
		Description: "Data source to retrieve the public key used to encrypt an organization's agent secrets.",
		Schema: map[string]*schema.Schema{
			"key_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the agent public key.",
			},
			"key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Base64-encoded agent public key.",
			},
		},
	}
}

func dataSourceGithubAgentsOrganizationPublicKeyRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, _ := m.(*Owner)
	if ok, diags := checkOrganizationOK(meta); !ok {
		return diags
	}

	key, _, err := meta.v3client.Agents.GetOrgPublicKey(ctx, meta.name)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(key.GetKeyID())
	if err := d.Set("key_id", key.GetKeyID()); err != nil {
		return diag.FromErr(err)
	}
	return diag.FromErr(d.Set("key", key.GetKey()))
}
