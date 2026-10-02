package masque

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("masque", parseGlobalOption)
	httpcaddyfile.RegisterHandlerDirective("masque", parseHandlerDirective)
	// Ahead of every handler that reads request bodies or answers requests,
	// so tunnels are not cut short and CONNECT-IP reaches the handler.
	httpcaddyfile.RegisterDirectiveOrder("masque", httpcaddyfile.Before, "header")
}

// parseGlobalOption sets up the masque app:
//
//	masque {
//	    ipv4                   <address/prefix>
//	    ipv6                   <address/prefix>
//	    interface              <name>
//	    mtu                    <bytes>
//	    manage_network         on|off
//	    block                  <prefix...>|none
//	    allow_client_to_client
//	    allow_host_access
//	    http3                  on|off
//	    mtu_probe              on|off
//	    max_sessions           <n>|unlimited
//	    user                   <name> <argon2id hash>
//	}
func parseGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	if existing != nil {
		return nil, d.Err("the masque global option is given twice")
	}
	app := new(App)
	d.Next() // the option name
	if d.NextArg() {
		return nil, d.ArgErr()
	}
	onOff := func() (*bool, error) {
		if !d.NextArg() {
			return nil, d.ArgErr()
		}
		var v bool
		switch d.Val() {
		case "on":
			v = true
		case "off":
		default:
			return nil, d.Errf("%s: expected on or off, got %q", d.Val(), d.Val())
		}
		if d.NextArg() {
			return nil, d.ArgErr()
		}
		return &v, nil
	}
	single := func(dst *string) error {
		if *dst != "" {
			return d.Errf("%s is given twice", d.Val())
		}
		if !d.NextArg() {
			return d.ArgErr()
		}
		*dst = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
		return nil
	}
	for d.NextBlock(0) {
		var err error
		switch d.Val() {
		case "interface":
			err = single(&app.Interface)
		case "ipv4":
			err = single(&app.IPv4)
		case "ipv6":
			err = single(&app.IPv6)
		case "mtu":
			var s string
			if err = single(&s); err == nil {
				if app.MTU, err = strconv.Atoi(s); err != nil {
					return nil, d.Errf("mtu: %v", err)
				}
			}
		case "manage_network":
			app.ManageNetwork, err = onOff()
		case "http3":
			app.HTTP3, err = onOff()
		case "mtu_probe":
			app.MTUProbe, err = onOff()
		case "allow_client_to_client":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			app.AllowClientToClient = true
		case "max_sessions":
			var s string
			if err = single(&s); err == nil {
				switch n, perr := strconv.Atoi(s); {
				case s == "unlimited":
					app.MaxSessions = -1
				case perr != nil || n < 1:
					return nil, d.Errf("max_sessions: expected a positive number or unlimited, got %q", s)
				default:
					app.MaxSessions = n
				}
			}
		case "allow_host_access":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			app.AllowHostAccess = true
		case "block":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.ArgErr()
			}
			if app.BlockedDestinations == nil {
				app.BlockedDestinations = &[]string{}
			}
			if len(args) == 1 && args[0] == "none" {
				continue
			}
			*app.BlockedDestinations = append(*app.BlockedDestinations, args...)
		case "user":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return nil, d.Errf("user: expected a name and a password hash")
			}
			app.Users = append(app.Users, User{Name: args[0], PasswordHash: args[1]})
		default:
			return nil, d.Errf("unknown masque option %q", d.Val())
		}
		if err != nil {
			return nil, err
		}
	}
	return httpcaddyfile.App{Name: "masque", Value: caddyconfig.JSON(app, nil)}, nil
}

// parseHandlerDirective sets up the handler:
//
//	masque [<template>]
//
// where the template is the path and query of the URI Template the clients
// use, by default /.well-known/masque/ip/{target}/{ipproto}/.
func parseHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(Handler)
	h.Next() // the directive name
	if h.NextArg() {
		handler.Template = h.Val()
	}
	if h.NextArg() || h.NextBlock(0) {
		return nil, h.ArgErr()
	}
	return handler, nil
}
