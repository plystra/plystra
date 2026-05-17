package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/plystra/plystra/ent"
	entadmingrant "github.com/plystra/plystra/ent/admingrant"
	entuser "github.com/plystra/plystra/ent/user"
	entusermember "github.com/plystra/plystra/ent/usermember"
)

func runAdmin(ctx context.Context, command string, args []string) error {
	switch command {
	case "bootstrap-super-admin":
		return bootstrapSuperAdmin(ctx, args)
	default:
		return fmt.Errorf("unknown admin command %q", command)
	}
}

func bootstrapSuperAdmin(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("bootstrap-super-admin", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	userID := flags.String("user-id", "", "existing User ID to receive the first instance super admin grant")
	memberID := flags.String("member-id", "", "optional Member ID to annotate the grant")
	grantID := flags.String("grant-id", "", "optional AdminGrant ID")
	ifExists := flags.String("if-exists", "error", "behavior when an active instance super admin grant already exists: error or ok")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*userID) == "" {
		return fmt.Errorf("--user-id is required")
	}
	onExists := strings.TrimSpace(*ifExists)
	if onExists == "" {
		onExists = "error"
	}
	if onExists != "error" && onExists != "ok" {
		return fmt.Errorf("--if-exists must be error or ok")
	}
	client, db, err := openEntClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	defer db.Close()

	now := time.Now().UTC()
	count, err := client.AdminGrant.Query().
		Where(
			entadmingrant.Level("instance_super_admin"),
			entadmingrant.Status("active"),
			entadmingrant.DeletedAtIsNil(),
			entadmingrant.RevokedAtIsNil(),
			entadmingrant.Or(entadmingrant.ExpiresAtIsNil(), entadmingrant.ExpiresAtGT(now)),
		).
		Count(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		if onExists == "ok" {
			fmt.Println("active instance_super_admin grant already exists")
			return nil
		}
		return fmt.Errorf("active instance_super_admin grant already exists; use the AdminGrant API as an existing super admin")
	}
	if _, err := client.User.Query().Where(entuser.ID(strings.TrimSpace(*userID)), entuser.DeletedAtIsNil()).Only(ctx); err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("user %q was not found", strings.TrimSpace(*userID))
		}
		return err
	}
	resolvedMemberID := strings.TrimSpace(*memberID)
	if resolvedMemberID == "" {
		binding, err := client.UserMember.Query().
			Where(
				entusermember.UserID(strings.TrimSpace(*userID)),
				entusermember.Status("active"),
				entusermember.DeletedAtIsNil(),
				entusermember.RevokedAtIsNil(),
				entusermember.Or(entusermember.ExpiresAtIsNil(), entusermember.ExpiresAtGT(now)),
			).
			Order(entusermember.ByIsPrimary(), entusermember.ByCreatedAt()).
			First(ctx)
		if err == nil {
			resolvedMemberID = binding.MemberID
		} else if !ent.IsNotFound(err) {
			return err
		}
	}
	id := strings.TrimSpace(*grantID)
	if id == "" {
		id = "ag_" + strings.NewReplacer("-", "_", ".", "_", "@", "_").Replace(strings.TrimSpace(*userID)) + "_instance_super_admin"
	}
	grant, err := client.AdminGrant.Create().
		SetID(id).
		SetUserID(strings.TrimSpace(*userID)).
		SetNillableMemberID(optionalStringPtr(resolvedMemberID)).
		SetLevel("instance_super_admin").
		SetPermissionKey("*").
		SetStatus("active").
		SetMetadata(map[string]any{"source": "plystractl bootstrap-super-admin"}).
		Save(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("created instance_super_admin grant %s for user %s\n", grant.ID, grant.UserID)
	return nil
}

func optionalStringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
