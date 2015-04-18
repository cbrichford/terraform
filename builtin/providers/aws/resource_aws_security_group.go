package aws

import (
	"bytes"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

func securityGroupHash(v interface{}) int {
	return hashcode.String(v.(string))
}

func resourceAwsSecurityGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsSecurityGroupCreate,
		Read:   resourceAwsSecurityGroupRead,
		Update: resourceAwsSecurityGroupUpdate,
		Delete: resourceAwsSecurityGroupDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"description": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			"vpc_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Computed: true,
			},

			"ingress": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"from_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"to_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"protocol": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"cidr_blocks": &schema.Schema{
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},

						"security_groups": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      securityGroupHash,
						},

						"self": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
				Set: resourceAwsSecurityGroupRuleHash,
			},

			"egress": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Default:  &schema.Set{F: resourceAwsSecurityGroupRuleHash},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"from_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"to_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},

						"protocol": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						"cidr_blocks": &schema.Schema{
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},

						"security_groups": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Set:      securityGroupHash,
						},

						"self": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
				Set: resourceAwsSecurityGroupRuleHash,
			},

			"owner_id": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			"tags": tagsSchema(),
		},
	}
}

func resourceAwsSecurityGroupCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2SDKconn

	securityGroupOpts := &ec2.CreateSecurityGroupInput{
		GroupName: aws.String(d.Get("name").(string)),
	}

	if v := d.Get("vpc_id"); v != nil {
		securityGroupOpts.VPCID = aws.String(v.(string))
	}

	if v := d.Get("description"); v != nil {
		securityGroupOpts.Description = aws.String(v.(string))
	}

	log.Printf(
		"[DEBUG] Security Group create configuration: %#v", securityGroupOpts)
	createResp, err := conn.CreateSecurityGroup(securityGroupOpts)
	if err != nil {
		return fmt.Errorf("Error creating Security Group: %s", err)
	}

	d.SetId(*createResp.GroupID)

	log.Printf("[INFO] Security Group ID: %s", d.Id())

	// Wait for the security group to truly exist
	log.Printf(
		"[DEBUG] Waiting for Security Group (%s) to exist",
		d.Id())
	stateConf := &resource.StateChangeConf{
		Pending: []string{""},
		Target:  "exists",
		Refresh: SGStateRefreshFunc(conn, d.Id()),
		Timeout: 1 * time.Minute,
	}
	if _, err := stateConf.WaitForState(); err != nil {
		return fmt.Errorf(
			"Error waiting for Security Group (%s) to become available: %s",
			d.Id(), err)
	}

	return resourceAwsSecurityGroupUpdate(d, meta)
}

func readRuleField(r schema.FieldReader, key []string) (interface{}, error) {
	readResultRaw, err := r.ReadField(key)
	log.Printf("readRuleField k: %+v r: %+v err: %+v", key, readResultRaw, err)

	if err != nil {
		return nil, err
	}
	return readResultRaw.Value, nil
}

func copyRuleMap(ruleMap map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range ruleMap {
		result[k] = v
	}
	return result
}

func castRules(rules interface{}) []map[string]interface{} {
	var rulesList []map[string]interface{}
	rulesList, ok := rules.([]map[string]interface{})
	if !ok {
		rulesList := make([]map[string]interface{}, 0)
		rawList := rules.([]interface{})
		for _, r := range rawList {
			rulesList = append(rulesList, r.(map[string]interface{}))
		}
	}
	return rulesList
}

func chooseRuleValue(name string,
	rawRule map[string]interface{},
	configRule map[string]interface{}) (interface{}, bool, bool) {
	value, ok := configRule[name]
	if ok {
		return value, true, true
	}
	value, ok = rawRule[name]
	return value, false, ok
}

func copyRuleValue(name string,
	srcRawRule map[string]interface{},
	srcConfigRule map[string]interface{},
	destRawRule map[string]interface{},
	destConfigRule map[string]interface{}) interface{} {
	value, finalValueKnown, exists := chooseRuleValue(name, srcRawRule, srcConfigRule)
	if !exists {
		return nil
	}
	destRawRule[name] = value
	if finalValueKnown {
		destConfigRule[name] = value
	}
	return value
}

func normalizeSecurityGroupRules(groupId string,
	rawRules interface{},
	configRules interface{}) ([]map[string]interface{}, []map[string]interface{}, error) {
	destRawRules := make([]map[string]interface{}, 0)
	destConfigRules := make([]map[string]interface{}, 0)

	if rawRules == nil {
		return destRawRules, destConfigRules, nil
	}
	srcRawRulesSlice := castRules(rawRules)
	configRulesSlice := castRules(configRules)

	for i, srcRawRule := range srcRawRulesSlice {
		srcConfigRule := configRulesSlice[i]
		baseRawRule := make(map[string]interface{})
		baseConfigRule := make(map[string]interface{})

		copyRuleValue("from_port", srcRawRule, srcConfigRule, baseRawRule, baseConfigRule)
		copyRuleValue("to_port", srcRawRule, srcConfigRule, baseRawRule, baseConfigRule)
		copyRuleValue("protocol", srcRawRule, srcConfigRule, baseRawRule, baseConfigRule)
		selfRaw := copyRuleValue("self", srcRawRule, srcConfigRule, baseRawRule, baseConfigRule)

		cidrBlocksRaw, cidrBlocksKnown, cidrBlocksExists := chooseRuleValue("cidr_blocks", srcRawRule, srcConfigRule)
		secGroupsRaw, secGroupsKnown, secGroupsExists := chooseRuleValue("security_groups", srcRawRule, srcConfigRule)

		log.Printf("cidrBlocksRaw: %+v", cidrBlocksRaw)
		log.Printf("secGroupsRaw: %+v", secGroupsRaw)

		if selfRaw != nil {
			self, ok := selfRaw.(bool)
			if self && ok {
				newRawRule := copyRuleMap(baseRawRule)
				newConfigRule := copyRuleMap(baseConfigRule)
				newRawRule["self"] = true
				newConfigRule["self"] = true

				destRawRules = append(destRawRules, newRawRule)
				destConfigRules = append(destConfigRules, newConfigRule)
			}
		}

		if cidrBlocksRaw != nil && cidrBlocksExists {
			cidrBlocks := cidrBlocksRaw.([]interface{})
			for _, cidrBlock := range cidrBlocks {
				newRawRule := copyRuleMap(baseRawRule)
				newConfigRule := copyRuleMap(baseConfigRule)
				newCIDRBlocks := []interface{}{cidrBlock}
				if cidrBlocksKnown {
					newConfigRule["cidr_blocks"] = newCIDRBlocks
				}
				newRawRule["cidr_blocks"] = newCIDRBlocks

				destRawRules = append(destRawRules, newRawRule)
				destConfigRules = append(destConfigRules, newConfigRule)
			}
		}

		if secGroupsRaw != nil && secGroupsExists {
			securityGroups := secGroupsRaw.([]interface{})
			for _, securityGroupRaw := range securityGroups {
				// Skip a security group reference that is covered
				// by 'self' above
				securityGroup, _ := securityGroupRaw.(string)
				if securityGroup == groupId {
					continue
				}
				newRawRule := copyRuleMap(baseRawRule)
				newConfigRule := copyRuleMap(baseConfigRule)
				newSecGroups := []interface{}{securityGroup}
				if secGroupsKnown {
					newConfigRule["security_groups"] = newSecGroups
				} else if !strings.Contains(securityGroup, "${") {
					newConfigRule["security_groups"] = newSecGroups
				}
				newRawRule["security_groups"] = newSecGroups

				destRawRules = append(destRawRules, newRawRule)
				destConfigRules = append(destConfigRules, newConfigRule)
			}
		}
	}
	log.Printf("normalizeSecurityGroup Raw: %+v Config: %+v", destRawRules, destConfigRules)
	return destRawRules, destConfigRules, nil
}

func (p *AWSProvider) diffSecurityGroups(
	r *schema.Resource,
	s *terraform.InstanceState,
	c *terraform.ResourceConfig) (*terraform.InstanceDiff, error) {

	// Copy the schem map without the egress and ingress entries, we do this
	// so that the diff will ignore these fields.  We'll check those by hand.

	var egressSchema *schema.Schema
	var ingressSchema *schema.Schema

	noRulesSchema := make(map[string]*schema.Schema)
	for k, v := range r.Schema {
		switch k {
		case "egress":
			egressSchema = v
		case "ingress":
			ingressSchema = v
		default:
			noRulesSchema[k] = v
		}
	}

	noRulesResource := *r
	noRulesResource.Schema = noRulesSchema

	noRulesDiff, err := noRulesResource.Diff(s, c)
	if err != nil {
		return nil, err
	}

	log.Printf("Raw ingress: %+v Config ingress: %+v ComputedKeys: %+v", c.Raw["ingress"], c.Config["ingress"], c.ComputedKeys)

	rulesSchema := make(map[string]*schema.Schema)
	rulesSchema["egress"] = egressSchema
	rulesSchema["ingress"] = ingressSchema

	rulesResource := *r
	rulesResource.Schema = rulesSchema

	resourceConfigCopy := terraform.NewResourceConfig(nil)
	resourceConfigCopy.ComputedKeys = c.ComputedKeys
	resourceConfigCopy.Raw = make(map[string]interface{})
	resourceConfigCopy.Config = make(map[string]interface{})
	egressSliceRaw, egressSliceConfig, _ := normalizeSecurityGroupRules(s.ID, c.Raw["egress"], c.Config["egress"])
	resourceConfigCopy.Raw["egress"] = egressSliceRaw
	resourceConfigCopy.Config["egress"] = egressSliceConfig

	ingressSliceRaw, ingressSliceConfig, _ := normalizeSecurityGroupRules(s.ID, c.Raw["ingress"], c.Config["ingress"])
	resourceConfigCopy.Raw["ingress"] = ingressSliceRaw
	resourceConfigCopy.Config["ingress"] = ingressSliceConfig

	rulesDiff, err := rulesResource.Diff(s, resourceConfigCopy)

	if err != nil {
		return nil, err
	}

	var destroy bool = false
	var destroyTainted bool = false
	var empty = true
	diffMap := make(map[string]*terraform.ResourceAttrDiff)

	if noRulesDiff != nil && !noRulesDiff.Empty() {
		destroy = destroy || noRulesDiff.Destroy
		destroyTainted = destroyTainted || noRulesDiff.DestroyTainted
		empty = empty && noRulesDiff.Empty()

		for k, v := range noRulesDiff.Attributes {
			diffMap[k] = v
		}
	}

	if rulesDiff != nil && !rulesDiff.Empty() {
		destroy = destroy || rulesDiff.Destroy
		destroyTainted = destroyTainted || rulesDiff.DestroyTainted
		empty = empty && rulesDiff.Empty()

		for k, v := range rulesDiff.Attributes {
			diffMap[k] = v
		}
	}

	if empty {
		return nil, nil
	}

	diff := &terraform.InstanceDiff{Attributes: diffMap,
		Destroy:        destroy,
		DestroyTainted: destroyTainted}

	for k, v := range diff.Attributes {
		log.Printf("myDiff k: %+v, v: %+v", k, v)
	}

	return diff, nil
}

func resourceAwsSecurityGroupRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2SDKconn

	sgRaw, _, err := SGStateRefreshFunc(conn, d.Id())()
	if err != nil {
		return err
	}
	if sgRaw == nil {
		d.SetId("")
		return nil
	}

	sg := sgRaw.(*ec2.SecurityGroup)

	ingressRules := resourceAwsSecurityGroupIPPermGather(d, sg.IPPermissions)
	egressRules := resourceAwsSecurityGroupIPPermGather(d, sg.IPPermissionsEgress)

	log.Printf("group: %v egressRules: %+v", d.Id(), egressRules)

	d.Set("description", sg.Description)
	d.Set("name", sg.GroupName)
	d.Set("vpc_id", sg.VPCID)
	d.Set("owner_id", sg.OwnerID)
	d.Set("ingress", ingressRules)
	d.Set("egress", egressRules)
	d.Set("tags", tagsToMapSDK(sg.Tags))
	return nil
}

func resourceAwsSecurityGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2SDKconn

	sgRaw, _, err := SGStateRefreshFunc(conn, d.Id())()
	if err != nil {
		return err
	}
	if sgRaw == nil {
		d.SetId("")
		return nil
	}

	group := sgRaw.(*ec2.SecurityGroup)

	err = resourceAwsSecurityGroupUpdateRules(d, "ingress", meta, group)
	if err != nil {
		return err
	}

	if d.Get("vpc_id") != nil {
		err = resourceAwsSecurityGroupUpdateRules(d, "egress", meta, group)
		if err != nil {
			return err
		}
	}

	if err := setTagsSDK(conn, d); err != nil {
		return err
	}

	d.SetPartial("tags")

	return resourceAwsSecurityGroupRead(d, meta)
}

func resourceAwsSecurityGroupDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2SDKconn

	log.Printf("[DEBUG] Security Group destroy: %v", d.Id())

	return resource.Retry(5*time.Minute, func() error {
		_, err := conn.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
			GroupID: aws.String(d.Id()),
		})
		if err != nil {
			ec2err, ok := err.(aws.APIError)
			if !ok {
				return err
			}

			switch ec2err.Code {
			case "InvalidGroup.NotFound":
				return nil
			case "DependencyViolation":
				// If it is a dependency violation, we want to retry
				return err
			default:
				// Any other error, we want to quit the retry loop immediately
				return resource.RetryError{Err: err}
			}
		}

		return nil
	})
}

func resourceAwsSecurityGroupRuleHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%d-", m["from_port"].(int)))
	buf.WriteString(fmt.Sprintf("%d-", m["to_port"].(int)))
	buf.WriteString(fmt.Sprintf("%s-", m["protocol"].(string)))
	buf.WriteString(fmt.Sprintf("%t-", m["self"].(bool)))

	// We need to make sure to sort the strings below so that we always
	// generate the same hash code no matter what is in the set.
	if v, ok := m["cidr_blocks"]; ok {
		vs := v.([]interface{})
		s := make([]string, len(vs))
		for i, raw := range vs {
			s[i] = raw.(string)
		}
		sort.Strings(s)

		for _, v := range s {
			buf.WriteString(fmt.Sprintf("%s-", v))
		}
	}
	if v, ok := m["security_groups"]; ok {
		vs := v.(*schema.Set).List()
		s := make([]string, len(vs))
		for i, raw := range vs {
			s[i] = raw.(string)
		}
		sort.Strings(s)

		for _, v := range s {
			buf.WriteString(fmt.Sprintf("%s-", v))
		}
	}

	return hashcode.String(buf.String())
}

func resourceAwsSecurityGroupIPPermGather(d *schema.ResourceData, permissions []*ec2.IPPermission) []map[string]interface{} {
	ruleSlice := make([]map[string]interface{}, len(permissions))
	for i, perm := range permissions {
		var fromPort int64 = 0
		var toPort int64 = 65535
		if v := perm.FromPort; v != nil {
			fromPort = *v
		}
		if v := perm.ToPort; v != nil {
			toPort = *v
		}
		m := make(map[string]interface{})
		ruleSlice[i] = m

		log.Printf("group: %v, from_port: %v, to_port: %v", d.Id(), fromPort, toPort)
		m["from_port"] = fromPort
		m["to_port"] = toPort
		m["protocol"] = *perm.IPProtocol
		if len(perm.IPRanges) > 0 {
			list := make([]string, 0, len(perm.IPRanges))

			for _, ip := range perm.IPRanges {
				list = append(list, *ip.CIDRIP)
			}
			m["cidr_blocks"] = list
		}

		var groups []string
		if len(perm.UserIDGroupPairs) > 0 {
			groups = flattenSecurityGroupsSDK(perm.UserIDGroupPairs)
		}

		if len(groups) > 0 {
			for i, id := range groups {
				if id == d.Id() {
					groups[i], groups = groups[len(groups)-1], groups[:len(groups)-1]
					m["self"] = true
				}
			}
			list := make([]string, 0, len(groups))
			list = append(list, groups...)
			m["security_groups"] = list
		}
	}
	return ruleSlice
}

func resourceAwsSecurityGroupUpdateRules(
	d *schema.ResourceData, ruleset string,
	meta interface{}, group *ec2.SecurityGroup) error {

	log.Printf("ruleset: %v", ruleset)

	if d.HasChange(ruleset) {
		o, n := d.GetChange(ruleset)
		if o == nil {
			o = new(schema.Set)
		}
		if n == nil {
			n = new(schema.Set)
		}

		os := o.(*schema.Set)
		ns := n.(*schema.Set)

		remove := expandIPPermsSDK(group, os.Difference(ns).List())
		add := expandIPPermsSDK(group, ns.Difference(os).List())

		// TODO: We need to handle partial state better in the in-between
		// in this update.

		// TODO: It'd be nicer to authorize before removing, but then we have
		// to deal with complicated unrolling to get individual CIDR blocks
		// to avoid authorizing already authorized sources. Removing before
		// adding is easier here, and Terraform should be fast enough to
		// not have service issues.

		if len(remove) > 0 || len(add) > 0 {
			conn := meta.(*AWSClient).ec2SDKconn

			var err error
			if len(remove) > 0 {
				log.Printf("[DEBUG] Revoking security group %#v %s rule: %#v",
					group, ruleset, remove)

				if ruleset == "egress" {
					req := &ec2.RevokeSecurityGroupEgressInput{
						GroupID:       group.GroupID,
						IPPermissions: remove,
					}
					_, err = conn.RevokeSecurityGroupEgress(req)
				} else {
					req := &ec2.RevokeSecurityGroupIngressInput{
						GroupID:       group.GroupID,
						IPPermissions: remove,
					}
					_, err = conn.RevokeSecurityGroupIngress(req)
				}

				if err != nil {
					return fmt.Errorf(
						"Error authorizing security group %s rules: %s",
						ruleset, err)
				}
			}

			if len(add) > 0 {
				log.Printf("[DEBUG] Authorizing security group %#v %s rule: %#v",
					group, ruleset, add)
				// Authorize the new rules
				if ruleset == "egress" {
					req := &ec2.AuthorizeSecurityGroupEgressInput{
						GroupID:       group.GroupID,
						IPPermissions: add,
					}
					_, err = conn.AuthorizeSecurityGroupEgress(req)
				} else {
					req := &ec2.AuthorizeSecurityGroupIngressInput{
						GroupID:       group.GroupID,
						IPPermissions: add,
					}
					if group.VPCID == nil || *group.VPCID == "" {
						req.GroupID = nil
						req.GroupName = group.GroupName
					}

					_, err = conn.AuthorizeSecurityGroupIngress(req)
				}

				if err != nil {
					return fmt.Errorf(
						"Error authorizing security group %s rules: %s",
						ruleset, err)
				}
			}
		}
	}
	return nil
}

// SGStateRefreshFunc returns a resource.StateRefreshFunc that is used to watch
// a security group.
func SGStateRefreshFunc(conn *ec2.EC2, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		req := &ec2.DescribeSecurityGroupsInput{
			GroupIDs: []*string{aws.String(id)},
		}
		resp, err := conn.DescribeSecurityGroups(req)
		if err != nil {
			if ec2err, ok := err.(aws.APIError); ok {
				if ec2err.Code == "InvalidSecurityGroupID.NotFound" ||
					ec2err.Code == "InvalidGroup.NotFound" {
					resp = nil
					err = nil
				}
			}

			if err != nil {
				log.Printf("Error on SGStateRefresh: %s", err)
				return nil, "", err
			}
		}

		if resp == nil {
			return nil, "", nil
		}

		group := resp.SecurityGroups[0]
		return group, "exists", nil
	}
}
