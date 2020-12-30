// the web driver
package main

import (
	"log"
	"net"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/gofiber/fiber/v2"
)

// Record Value struct
type RecordValue struct {
	Value string `json:"value" xml:"value" form:"value"`
}

func modifyDNS(action string, c *fiber.Ctx) error {
	// create new var to extract stuff
	valueSet := new(RecordValue)
	// parse body
	if err := c.BodyParser(valueSet); err != nil {
		return err
	}
	// get required initial val
	zoneID := os.Getenv("ROUTE53_ZONE_ID")
	// start a AWS session
	sess := session.New(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
	})
	// generate the huge parameter
	params := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					// basically insert if not exist is UPSERT
					// delete is well delete
					Action: aws.String(action),
					// the record itself is a TXT record
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(c.Params("token") + "." + os.Getenv("BASE_DOMAIN")),
						Type: aws.String("TXT"),
						ResourceRecords: []*route53.ResourceRecord{
							{
								Value: aws.String(valueSet.Value),
							},
						},
						TTL:    aws.Int64(10),
						Weight: aws.Int64(0),
					},
				},
			},
		},
		// ID of the zone
		HostedZoneId: aws.String(zoneID),
	}
	// start a session with route53
	svc := route53.New(sess)
	// run the change
	resp, err := svc.ChangeResourceRecordSets(params)
	if err != nil {
		return err
	}
	// send response
	return c.SendString(resp.String())
}

func main() {
	app := fiber.New()
	// Read
	app.Get("/:token", func(c *fiber.Ctx) error {
		// basic DNS query
		baseDomain := os.Getenv("BASE_DOMAIN")
		baseDomain = c.Params("token") + "." + baseDomain
		res, err := net.LookupTXT(baseDomain)
		if err != nil {
			return err
		}
		return c.SendString(res[0])
	})

	// Create
	app.Put("/:token", func(c *fiber.Ctx) error {
		return modifyDNS("UPSERT", c)
	})
	// Update
	app.Patch("/:token", func(c *fiber.Ctx) error {
		return modifyDNS("UPSERT", c)
	})
	// Delete
	app.Delete("/:token", func(c *fiber.Ctx) error {
		return modifyDNS("DELETE", c)
	})
	// starts listener
	log.Fatal(app.Listen(":6443"))
}
