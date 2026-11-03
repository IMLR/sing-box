package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

const (
	applyMixedPort uint16 = 31080
	applyEchoA     uint16 = 31081
	applyEchoB     uint16 = 31082
	applyClashPort uint16 = 31083
)

// applyConfig renders a small configuration: a mixed inbound, direct nodes, a
// selector over them, and a reject rule per listed port.
func applyConfig(t *testing.T, nodes map[string]string, groups map[string][]string, rejectPorts []uint16, extra string) option.Options {
	outbounds := ""
	for tag, extraOptions := range nodes {
		outbounds += fmt.Sprintf(`{"type":"direct","tag":%q%s},`, tag, extraOptions)
	}
	for tag, members := range groups {
		raw, _ := json.Marshal(members)
		outbounds += fmt.Sprintf(`{"type":"selector","tag":%q,"outbounds":%s},`, tag, raw)
	}
	rules := ""
	for _, port := range rejectPorts {
		rules += fmt.Sprintf(`{"port":[%d],"action":"reject"},`, port)
	}
	content := fmt.Sprintf(`{
		"log":{"level":"warning"},
		"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],
		"outbounds":[%s],
		"route":{"rules":[%s]%s,"final":"group"}
	}`, applyMixedPort, outbounds[:len(outbounds)-1], trimComma(rules), extra)
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, []byte(content))
	require.NoError(t, err)
	return options
}

func trimComma(s string) string {
	if s == "" {
		return s
	}
	return s[:len(s)-1]
}

func startApplyInstance(t *testing.T, options option.Options) *box.Box {
	ctx, cancel := context.WithCancel(globalCtx)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	return instance
}

func startEcho(t *testing.T, port uint16) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
}

func dialThrough(port uint16) (net.Conn, error) {
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", applyMixedPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dialer.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", port))
}

func echoOnce(conn net.Conn, message string) error {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(message)); err != nil {
		return err
	}
	buffer := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		return err
	}
	if string(buffer) != message {
		return fmt.Errorf("echo mismatch: %q", buffer)
	}
	return nil
}

func reachable(port uint16) bool {
	conn, err := dialThrough(port)
	if err != nil {
		return false
	}
	defer conn.Close()
	return echoOnce(conn, "probe") == nil
}

func selectorNow(t *testing.T, instance *box.Box, tag string) string {
	outbound, loaded := instance.Outbound().Outbound(tag)
	require.True(t, loaded, tag)
	return outbound.(adapter.OutboundGroup).Now()
}

func TestApplyKeepsConnectionsAcrossChanges(t *testing.T) {
	startEcho(t, applyEchoA)
	startEcho(t, applyEchoB)
	instance := startApplyInstance(t, applyConfig(t,
		map[string]string{"node-a": "", "node-b": ""},
		map[string][]string{"group": {"node-a", "node-b"}},
		[]uint16{applyEchoB}, ""))

	require.True(t, reachable(applyEchoA))
	require.False(t, reachable(applyEchoB), "port B starts rejected")

	held, err := dialThrough(applyEchoA)
	require.NoError(t, err)
	defer held.Close()
	require.NoError(t, echoOnce(held, "before"))
	group, _ := instance.Outbound().Outbound("group")
	group.(interface{ SelectOutbound(string) bool }).SelectOutbound("node-b")

	// Add a node and a group, change a node, change the group's members and
	// swap which port is rejected.
	result, err := instance.Apply(applyConfig(t,
		map[string]string{"node-a": "", "node-b": `,"tcp_fast_open":true`, "node-c": ""},
		map[string][]string{"group": {"node-a", "node-b", "node-c"}, "group2": {"node-c"}},
		[]uint16{applyEchoA}, ""))
	require.NoError(t, err)
	require.Empty(t, result.RestartRequired)
	require.ElementsMatch(t, []string{"node-c", "group2"}, result.Outbounds.Added)
	require.Equal(t, []string{"node-b"}, result.Outbounds.Updated)
	require.Equal(t, []string{"group"}, result.Outbounds.Regrouped)
	require.True(t, result.RouteRules)

	require.NoError(t, echoOnce(held, "after"), "a connection open before the apply carries on")
	require.Equal(t, "node-b", selectorNow(t, instance, "group"), "selection kept on the recreated node")
	require.False(t, reachable(applyEchoA), "new rules apply to new connections")
	require.True(t, reachable(applyEchoB))
	nodeB, _ := instance.Outbound().Outbound("node-b")
	group, _ = instance.Outbound().Outbound("group")
	require.Same(t, nodeB, group.(interface{ Selected() adapter.Outbound }).Selected(), "group rebound to the new node-b")

	// Remove what was added; groups go before the nodes they hold.
	result, err = instance.Apply(applyConfig(t,
		map[string]string{"node-a": "", "node-b": `,"tcp_fast_open":true`},
		map[string][]string{"group": {"node-a", "node-b"}},
		[]uint16{applyEchoA}, ""))
	require.NoError(t, err)
	require.Equal(t, []string{"group2", "node-c"}, result.Outbounds.Removed)
	_, loaded := instance.Outbound().Outbound("node-c")
	require.False(t, loaded)
	require.NoError(t, echoOnce(held, "still"))

	// The same configuration again changes nothing.
	result, err = instance.Apply(applyConfig(t,
		map[string]string{"node-a": "", "node-b": `,"tcp_fast_open":true`},
		map[string][]string{"group": {"node-a", "node-b"}},
		[]uint16{applyEchoA}, ""))
	require.NoError(t, err)
	require.False(t, result.Changed())
	require.Empty(t, result.RestartRequired)
}

func TestApplyRemovingSelectedMemberMovesSelection(t *testing.T) {
	startEcho(t, applyEchoA)
	instance := startApplyInstance(t, applyConfig(t,
		map[string]string{"node-a": "", "node-b": ""},
		map[string][]string{"group": {"node-a", "node-b"}}, nil, ""))
	group, _ := instance.Outbound().Outbound("group")
	group.(interface{ SelectOutbound(string) bool }).SelectOutbound("node-b")

	result, err := instance.Apply(applyConfig(t,
		map[string]string{"node-a": ""},
		map[string][]string{"group": {"node-a"}}, nil, ""))
	require.NoError(t, err)
	require.Equal(t, []string{"node-b"}, result.Outbounds.Removed)
	require.Equal(t, "node-a", selectorNow(t, instance, "group"))
	require.True(t, reachable(applyEchoA))
}

func TestApplyAddsLocalRuleSet(t *testing.T) {
	startEcho(t, applyEchoA)
	directory := t.TempDir()
	ruleFile := filepath.Join(directory, "block.json")
	require.NoError(t, os.WriteFile(ruleFile, []byte(`{"version":1,"rules":[{"port":[31081]}]}`), 0o644))
	instance := startApplyInstance(t, applyConfig(t,
		map[string]string{"node-a": ""},
		map[string][]string{"group": {"node-a"}}, nil, ""))
	require.True(t, reachable(applyEchoA))

	ruleSet := fmt.Sprintf(`,"rule_set":[{"tag":"block","type":"local","format":"source","path":%q}]`, ruleFile)
	options := applyConfig(t, map[string]string{"node-a": ""}, map[string][]string{"group": {"node-a"}}, nil, ruleSet)
	options.Route.Rules = append(options.Route.Rules, mustRule(t, `{"rule_set":["block"],"action":"reject"}`))
	result, err := instance.Apply(options)
	require.NoError(t, err)
	require.Equal(t, []string{"block"}, result.RuleSetsAdded)
	require.False(t, reachable(applyEchoA), "the added rule-set is in effect")
}

func TestApplyRefusesInboundChanges(t *testing.T) {
	instance := startApplyInstance(t, applyConfig(t,
		map[string]string{"node-a": ""},
		map[string][]string{"group": {"node-a"}}, nil, ""))
	options := applyConfig(t, map[string]string{"node-a": "", "node-z": ""},
		map[string][]string{"group": {"node-a"}}, nil, "")
	options.Inbounds[0].Tag = "renamed"
	result, err := instance.Apply(options)
	require.NoError(t, err)
	require.Contains(t, result.RestartRequired, "inbounds changed")
	_, loaded := instance.Outbound().Outbound("node-z")
	require.False(t, loaded, "nothing is applied when a reload is needed")
}

func mustRule(t *testing.T, content string) option.Rule {
	rule, err := json.UnmarshalExtendedContext[option.Rule](globalCtx, []byte(content))
	require.NoError(t, err)
	return rule
}

func TestApplyUnderConcurrentConnections(t *testing.T) {
	startEcho(t, applyEchoA)
	startEcho(t, applyEchoB)
	configA := applyConfig(t,
		map[string]string{"node-a": "", "node-b": ""},
		map[string][]string{"group": {"node-a", "node-b"}}, nil, "")
	configB := applyConfig(t,
		map[string]string{"node-a": `,"tcp_fast_open":true`, "node-c": ""},
		map[string][]string{"group": {"node-c", "node-a"}, "group2": {"node-c"}}, []uint16{applyEchoB}, "")
	instance := startApplyInstance(t, configA)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures := make(chan error, 64)
	done := make(chan struct{})
	for worker := 0; worker < 8; worker++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for ctx.Err() == nil {
				conn, err := dialThrough(applyEchoA)
				if err != nil {
					failures <- err
					continue
				}
				if err = echoOnce(conn, "load"); err != nil {
					failures <- err
				}
				conn.Close()
			}
		}()
	}
	for i := 0; i < 50; i++ {
		options := configA
		if i%2 == 0 {
			options = configB
		}
		result, err := instance.Apply(options)
		require.NoError(t, err)
		require.Empty(t, result.RestartRequired)
	}
	cancel()
	for worker := 0; worker < 8; worker++ {
		<-done
	}
	close(failures)
	var errors []error
	for err := range failures {
		errors = append(errors, err)
	}
	require.Empty(t, errors, "port A is never rejected and must stay reachable throughout")
}

type applierFunc func() (*adapter.ApplyResult, error)

func (f applierFunc) ApplyConfig() (*adapter.ApplyResult, error) { return f() }

type checkerFunc func() error

func (f checkerFunc) CheckConfig() error { return f() }

// POST /configs/apply answers with what changed, also when the change needs a
// reload and ?reload=true asks for one.
func TestApplyEndpointReportsReload(t *testing.T) {
	options := applyConfig(t, map[string]string{"a": ""}, map[string][]string{"group": {"a"}}, nil, "")
	options.Experimental = &option.ExperimentalOptions{ClashAPI: &option.ClashAPIOptions{
		ExternalController: fmt.Sprintf("127.0.0.1:%d", applyClashPort),
	}}
	ctx, cancel := context.WithCancel(service.ExtendContext(globalCtx))
	// as sing-box run does: the reload routes exist only with a checker
	service.MustRegister[adapter.ConfigChecker](ctx, checkerFunc(func() error { return nil }))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() {
		instance.Close()
		cancel()
	})
	service.MustRegister[adapter.ConfigApplier](ctx, applierFunc(func() (*adapter.ApplyResult, error) {
		return &adapter.ApplyResult{RestartRequired: []string{"log", "dns"}}, nil
	}))

	url := fmt.Sprintf("http://127.0.0.1:%d/configs/apply?reload=true", applyClashPort)
	var response *http.Response
	require.Eventually(t, func() bool {
		response, err = http.Post(url, "application/json", nil)
		return err == nil
	}, 5*time.Second, 50*time.Millisecond, "apply request: %v", err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var result adapter.ApplyResult
	require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
	require.Equal(t, []string{"log", "dns"}, result.RestartRequired)
}
