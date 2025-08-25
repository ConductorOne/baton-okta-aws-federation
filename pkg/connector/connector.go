package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/session"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/okta/okta-sdk-golang/v2/okta"

	cfg "github.com/conductorone/baton-okta-aws-federation/pkg/config"
)

// TODO: use isNotFoundError() since E0000008 is also a not found error
const ResourceNotFoundExceptionErrorCode = "E0000007"
const AccessDeniedErrorCode = "E0000006"
const ExpectedGroupNameCaptureGroupsWithGroupFilterForMultipleAWSInstances = 3

var (
	// Cache namespace prefixes.
	appGroupPrefix    = sessions.WithPrefix("appGroup")
	notAppGroupPrefix = sessions.WithPrefix("notAppGroup")
	settingsPrefix    = sessions.WithPrefix("settings")
	settingsEntry     = "settings"
)

type Okta struct {
	client    *okta.Client
	clientV5  *oktav5.APIClient
	domain    string
	apiToken  string
	awsConfig *awsConfig
}

type awsConfig struct {
	OktaAppId                                             string
	AllowGroupToDirectAssignmentConversionForProvisioning bool
}

/*
JoinAllRoles: This option enables merging all available roles assigned to a user as follows:

For example, if a user is directly assigned Role1 and Role2 (user to app assignment),
and the user belongs to group GroupAWS with RoleA and RoleB assigned (group to app assignment), then:

Join all roles OFF: Role1 and Role2 are available upon login to AWS
Join all roles ON: Role1, Role2, RoleA, and RoleB are available upon login to AWS

UseGroupMapping: Use Group Mapping enables CONNECT OKTA TO MULTIPLE AWS INSTANCES VIA USER GROUPS functionality.

IdentityProviderArnRegex: Uses the "Role Value Pattern" to obtain a regular expression to extract the account id.
This is only used when UseGroupMapping is not enabled.

Role Value Pattern: This field takes the AWS role and account ID captured within the syntax of your AWS role groups,
and translates it into the proper syntax AWS requires in Okta’s SAML assertion to allow users to view their accounts and roles when they sign in.

This field should always follow this specific syntax:
arn:aws:iam::${accountid}:saml-provider/[SAML Provider Name],arn:aws:iam::${accountid}:role/${role}
*/
type oktaAWSAppSettings struct {
	JoinAllRoles                 bool
	IdentityProviderArn          string
	RoleRegex                    string
	UseGroupMapping              bool
	IdentityProviderArnAccountID string
	SamlRolesUnionEnabled        bool
}

type Config struct {
	Domain                                                string
	ApiToken                                              string
	Cache                                                 bool
	CacheTTI                                              int32
	CacheTTL                                              int32
	AWSOktaAppId                                          string
	AllowGroupToDirectAssignmentConversionForProvisioning bool
}

func v1AnnotationsForResourceType(resourceTypeID string, skipEntitlementsAndGrants bool) annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.V1Identifier{
		Id: resourceTypeID,
	})

	if skipEntitlementsAndGrants {
		annos.Update(&v2.SkipEntitlementsAndGrants{})
	}

	return annos
}

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: v1AnnotationsForResourceType("user", true),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
		Annotations: v1AnnotationsForResourceType("group", false),
	}
	resourceTypeAccount = &v2.ResourceType{
		Id:          "account",
		DisplayName: "Account",
		Annotations: v1AnnotationsForResourceType("account", false),
	}
)

func (o *Okta) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	resourceSyncer := []connectorbuilder.ResourceSyncerV2{accountBuilder(o)}
	return resourceSyncer
}

func (c *Okta) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	_, err := c.Validate(ctx)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(&v2.ExternalLink{
		Url: c.domain,
	})

	return &v2.ConnectorMetadata{
		DisplayName: "Okta",
		Description: "The Okta connector syncs user, group, role, and app data from Okta",
		Annotations: annos,
		AccountCreationSchema: &v2.ConnectorAccountCreationSchema{
			FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
				"first_name": {
					DisplayName: "First Name",
					Required:    true,
					Description: "This first name will be used for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "First name",
					Order:       1,
				},
				"last_name": {
					DisplayName: "Last Name",
					Required:    true,
					Description: "This last name will be used for the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Last name",
					Order:       2,
				},
				"email": {
					DisplayName: "Email",
					Required:    true,
					Description: "This will be the email of the user. If login is unset this is also the login.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Email",
					Order:       3,
				},
				"login": {
					DisplayName: "Login",
					Required:    false,
					Description: "This login will be used as the login for the user. Email will be used if login is not present.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Login",
					Order:       4,
				},
				"password_change_on_login_required": {
					DisplayName: "Password Change Required on Login",
					Required:    false,
					Description: "When creating accounts with a random password setting this to 'true' will require the user to change their password on first login.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "True/False",
					Order:       5,
				},
			},
		},
	}, nil
}

func (c *Okta) Validate(ctx context.Context) (annotations.Annotations, error) {
	if c.apiToken == "" {
		return nil, nil
	}

	token := newPaginationToken(defaultLimit, "")

	_, respCtx, err := getOrgSettings(ctx, c.clientV5, token)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: verify failed to fetch org: %w", err)
	}

	_, _, err = parseRespV5(respCtx.OktaResponse)
	if err != nil {
		return nil, fmt.Errorf("okta-connector: verify failed to parse response: %w", err)
	}

	if respCtx.OktaResponse.StatusCode != http.StatusOK {
		err := fmt.Errorf("okta-connector: verify returned non-200: '%d'", respCtx.OktaResponse.StatusCode)
		return nil, err
	}

	_, err = c.getAWSApplicationConfig(ctx, nil)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (c *Okta) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, fmt.Errorf("not implemented")
}

// safeCacheInt32 converts int to int32 with bounds checking.
func safeCacheInt32(val int) (int32, error) {
	if val > 2147483647 || val < 0 {
		return 0, fmt.Errorf("value %d is out of range for int32", val)
	}
	return int32(val), nil
}

func New(ctx context.Context, cc *cfg.OktaAwsFederation, opts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	var (
		oktaClient   *okta.Client
		oktaClientV5 *oktav5.APIClient
	)
	client, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, nil, err
	}

	cacheTTI, err := safeCacheInt32(cc.CacheTti)
	if err != nil {
		return nil, nil, err
	}

	cacheTTL, err := safeCacheInt32(cc.CacheTtl)
	if err != nil {
		return nil, nil, err
	}

	if cc.ApiToken != "" && cc.Domain != "" {
		_, oktaClient, err = okta.NewClient(ctx,
			okta.WithOrgUrl(fmt.Sprintf("https://%s", cc.Domain)),
			okta.WithToken(cc.ApiToken),
			okta.WithHttpClientPtr(client),
			okta.WithCache(cc.Cache),
			okta.WithCacheTti(cacheTTI),
			okta.WithCacheTtl(cacheTTL),
		)
		if err != nil {
			return nil, nil, err
		}

		config, err := oktav5.NewConfiguration(
			oktav5.WithOrgUrl(fmt.Sprintf("https://%s", cc.Domain)),
			oktav5.WithToken(cc.ApiToken),
			oktav5.WithHttpClientPtr(client),
			oktav5.WithCache(cc.Cache),
			oktav5.WithCacheTti(cacheTTI),
			oktav5.WithCacheTtl(cacheTTL),
			oktav5.WithRateLimitPrevent(true),
		)
		if err != nil {
			return nil, nil, err
		}
		oktaClientV5 = oktav5.NewAPIClient(config)
	}

	awsConfig := &awsConfig{
		OktaAppId: cc.AwsOktaAppId,
		AllowGroupToDirectAssignmentConversionForProvisioning: cc.AwsAllowGroupToDirectAssignmentConversionForProvisioning,
	}

	return &Okta{
		client:    oktaClient,
		domain:    cc.Domain,
		apiToken:  cc.ApiToken,
		clientV5:  oktaClientV5,
		awsConfig: awsConfig,
	}, nil, nil
}

func (c *Okta) getAWSApplicationConfig(ctx context.Context, ss sessions.SessionStore) (*oktaAWSAppSettings, error) {
	if c.awsConfig == nil {
		return nil, nil
	}

	if ss != nil {
		cachedSettings, found, err := session.GetJSON[oktaAWSAppSettings](ctx, ss, settingsEntry, settingsPrefix)

		if err == nil && found {
			return &cachedSettings, nil
		}
	}

	if c.awsConfig.OktaAppId == "" {
		return nil, fmt.Errorf("okta-connector: no app id set")
	}

	app, resp, err := c.clientV5.ApplicationAPI.GetApplication(ctx, c.awsConfig.OktaAppId).Execute()
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: verify failed to fetch aws app: %w", err)
	}
	awsAppRespCtx, err := responseToContextV5(&pagination.Token{}, resp)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: verify failed to convert get aws app response: %w", err)
	}
	if awsAppRespCtx.OktaResponse.StatusCode != http.StatusOK {
		err := fmt.Errorf("okta-connector: verify returned non-200 for aws app: '%d'", awsAppRespCtx.OktaResponse.StatusCode)
		return nil, err
	}

	appInstance := app.GetActualInstance()
	oktaApp, ok := appInstance.(*oktav5.SamlApplication)
	if !ok {
		if appInstance == nil {
			return nil, fmt.Errorf("okta-aws-connector: error getting actual instance of okta app")
		}
		return nil, fmt.Errorf("okta-aws-connector: error getting actual instance of okta app: unexpected type %T", appInstance)
	}
	if !strings.Contains(*oktaApp.Name, "aws") {
		return nil, fmt.Errorf("okta-aws-connector: okta app '%s' is not an aws app", *oktaApp.Name)
	}
	if oktaApp.Settings == nil {
		return nil, fmt.Errorf("okta-aws-connector: settings are not present on okta app")
	}
	if oktaApp.Settings.App == nil {
		return nil, fmt.Errorf("okta-aws-connector: app settings are not present on okta app")
	}
	appSettings := *oktaApp.Settings.App
	useGroupMapping, ok := appSettings.AdditionalProperties["useGroupMapping"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'useGroupMapping' app setting is not present on okta app settings")
	}
	useGroupMappingBool, ok := useGroupMapping.(bool)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'useGroupMapping' app setting is not boolean")
	}
	groupFilter, ok := appSettings.AdditionalProperties["groupFilter"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'groupFilter' app setting is not present on okta app settings")
	}
	groupFilterString, ok := groupFilter.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'groupFilter' app setting is not string")
	}
	joinAllRoles, ok := appSettings.AdditionalProperties["joinAllRoles"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'joinAllRoles' app setting is not present on okta app settings")
	}
	joinAllRolesBool, ok := joinAllRoles.(bool)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'joinAllRoles' app setting is not boolean")
	}
	identityProviderArn, ok := appSettings.AdditionalProperties["identityProviderArn"]
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'identityProviderArn' app setting is not present on okta app settings")
	}
	identityProviderArnString, ok := identityProviderArn.(string)
	if !ok {
		return nil, fmt.Errorf("okta-connector: 'identityProviderArn' app setting is not string")
	}

	groupFilterRegex := strings.Replace(groupFilterString, `(?{{accountid}}`, `(\d+`, 1)
	groupFilterRegex = strings.Replace(groupFilterRegex, `(?{{role}}`, `([a-zA-Z0-9+=,.@\\-_]+`, 1)

	// Unescape the groupFilterRegex regex string
	roleRegex := strings.ReplaceAll(groupFilterRegex, `\\`, `\`)

	// TODO(lauren) only do this if use group mapping not enabled?
	accountId, err := accountIdFromARN(identityProviderArnString)
	if err != nil {
		return nil, err
	}

	samlRolesUnionEnabled, err := isSamlRolesUnionEnabled(ctx, c.client, c.awsConfig.OktaAppId)
	if err != nil {
		return nil, err
	}

	oktaAWSAppSettings := &oktaAWSAppSettings{
		JoinAllRoles:                 joinAllRolesBool,
		IdentityProviderArn:          identityProviderArnString,
		RoleRegex:                    roleRegex,
		UseGroupMapping:              useGroupMappingBool,
		IdentityProviderArnAccountID: accountId,
		SamlRolesUnionEnabled:        samlRolesUnionEnabled,
	}


	if ss != nil {
		_ = session.SetJSON(ctx, ss, settingsEntry, *oktaAWSAppSettings, settingsPrefix)
	}

	return oktaAWSAppSettings, nil
}

type AppUserSchema struct {
	Definitions struct {
		Base struct {
			Properties struct {
				SamlRoles struct {
					Union string `json:"union,omitempty"`
				} `json:"samlRoles,omitempty"`
			} `json:"properties"`
		} `json:"base"`
	} `json:"definitions"`
}

func getDefaultAppUserSchema(ctx context.Context, client *okta.Client, appId string) (*AppUserSchema, error) {
	url := fmt.Sprintf(apiPathDefaultAppSchema, appId)
	rq := client.CloneRequestExecutor()
	req, err := rq.
		WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	var appUserSchema *AppUserSchema
	_, err = rq.Do(ctx, req, &appUserSchema)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: error fetching default application schema: %w", err)
	}
	return appUserSchema, nil
}

func isSamlRolesUnionEnabled(ctx context.Context, client *okta.Client, appId string) (bool, error) {
	defaultAppSchema, err := getDefaultAppUserSchema(ctx, client, appId)
	if err != nil {
		return false, err
	}
	if defaultAppSchema.Definitions.Base.Properties.SamlRoles.Union == "ENABLE" {
		return true, nil
	}
	return false, nil
}

func (a *oktaAWSAppSettings) getAppGroupFromCache(ctx context.Context, ss sessions.SessionStore, groupId string) (*OktaAppGroupWrapper, error) {
	cachedAppGroup, found, err := session.GetJSON[[]string](ctx, ss, groupId, appGroupPrefix)
	if err != nil {
		return nil, err
	} else if !found {
		return nil, nil
	}

	return &OktaAppGroupWrapper{
		samlRoles: cachedAppGroup,
	}, nil
}

func (a *oktaAWSAppSettings) setAppGroupInCache(ctx context.Context, ss sessions.SessionStore, groupId string, wrapper *OktaAppGroupWrapper) error {
	return session.SetJSON(ctx, ss, groupId, wrapper.samlRoles, appGroupPrefix)
}

func (a *oktaAWSAppSettings) checkIfNotAppGroupFromCache(ctx context.Context, ss sessions.SessionStore, groupId string) (bool, error) {
	notAppGroup, found, err := session.GetJSON[bool](ctx, ss, groupId, notAppGroupPrefix)
	if err != nil {
		return false, err
	} else if !found {
		return false, nil
	}

	return notAppGroup, nil
}

func (a *oktaAWSAppSettings) setNotAppGroupInCache(ctx context.Context, ss sessions.SessionStore, groupId string, value bool) error {
	return session.SetJSON(ctx, ss, groupId, value, notAppGroupPrefix)
}

func appGroupSAMLRolesWrapper(ctx context.Context, appGroup *okta.ApplicationGroupAssignment) (*OktaAppGroupWrapper, error) {
	samlRoles, err := getSAMLRolesFromAppGroupProfile(ctx, appGroup)
	if err != nil {
		return nil, err
	}
	return &OktaAppGroupWrapper{
		samlRoles: samlRoles,
	}, nil
}

func accountIdFromARN(input string) (string, error) {
	parsedArn, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("okta-aws-connector: invalid ARN: '%s': %w", input, err)
	}
	return parsedArn.AccountID, nil
}

// TODO: cleanup pagination token
func getOrgSettings(ctx context.Context, client *oktav5.APIClient, token *pagination.Token) (*oktav5.OrgSetting, *responseContextV5, error) {
	orgSettings, resp, err := client.OrgSettingAPI.GetOrgSettings(ctx).Execute()
	if err != nil {
		return nil, nil, handleOktaResponseErrorV5(resp, err)
	}

	respCtx, err := responseToContextV5(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return orgSettings, respCtx, nil
}
