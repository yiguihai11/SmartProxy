package lantern

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestInProcessSingBox_Compile(t *testing.T) {
	ctx := context.Background()
	boxCtx := include.Context(ctx)

	cfgJSON := []byte(`{
		"log": { "level": "warn" },
		"inbounds": [
			{
				"type": "socks",
				"tag": "socks-in",
				"listen": "127.0.0.1",
				"listen_port": 29999
			}
		],
		"outbounds": [
			{
				"type": "direct",
				"tag": "direct"
			}
		]
	}`)

	var opts option.Options
	if err := opts.UnmarshalJSONContext(boxCtx, cfgJSON); err != nil {
		t.Fatalf("UnmarshalJSONContext failed: %v", err)
	}

	instance, err := box.New(box.Options{
		Context: boxCtx,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("box.New failed: %v", err)
	}

	if err := instance.Start(); err != nil {
		t.Fatalf("instance.Start failed: %v", err)
	}
	defer instance.Close()
	t.Log("In-process sing-box started and closed successfully!")
}
