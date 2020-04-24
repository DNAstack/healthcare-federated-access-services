package processaws

import (
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"golang.org/x/net/context"
	"testing"
	"time"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

func TestKeyGc(t *testing.T) {
	store :=storage.NewMemoryStorage("dam", "testdata/config")
	accounts := []*clouds.Account {
		{ID: "1231231231", DisplayName: "ic_12345678|localhost.com"},
	}
	wh := clouds.NewMockAccountManager(accounts)
	processName := "aws_keys"
	gc := NewKeyGC(processName, wh, store, 10*time.Second, 2)
	if err := gc.process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("UpdateFlowControl(_,_) failed: %v", err)
	}
	waits := 0
	gc.WaitCondition(func(ctx context.Context, duration time.Duration) bool {
		waits++
		if waits > 1 {
			return false
		}
		return true
	})
	params := &pb.Process_Params {
		IntParams: map[string]int64{
			"foo": 1,
			"bar": 2,
		},
	}
	if _,err := gc.RegisterWork("test_process", params, nil); err != nil {
		t.Fatalf(`RegisterWork("test_process", %+v) failed: %v`, params, err)
	}
	if _, err := gc.RegisterWork("bad", nil, nil); err != nil {
		t.Fatalf(`RegisterWork("bad", nil) failed: %v`, err)
	}
	if err := gc.UnregisterWork("bad", nil); err != nil {
		t.Fatalf(`UnregisterWork("bad") failed: %v`, err)
	}

	gc.Run(context.Background())

	//state := &pb.Process{}

}
