package oauth2cli

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// DefaultPort is the default port for the local callback server.
const DefaultPort = 4321

// Token completes the OAuth2 flow, and returns a token from a code exchange.
//
// It stands up a temporary HTTP server on the host's localPort port in order to handle
// the OAuth2 callback. If an error occurs during the callback handling - such as
// invalid state, or a missing code, an error will be returned.
//
// The server will be shutdown after handling the first request, regardless of success or failure.
//
// If localPort is 0, it will use DefaultPort.
// The user's browser will be redirected to the URL provided. If it isn't, no redirect will occur.
func Token(ctx context.Context, cfg *oauth2.Config, localPort int, redirect string) (*oauth2.Token, error) {
	state := strconv.Itoa(rand.Int())
	url := cfg.AuthCodeURL(state)

	shutdown := make(chan struct{})
	errC := make(chan error, 2)

	var code string

	// OAuth2 callback handler on the default mux.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			close(errC)
			shutdown <- struct{}{}
		}()

		q := r.URL.Query()

		// Check state matches.
		if s := q.Get("state"); s != state {
			errC <- fmt.Errorf("invalid state received: %s, expected %s", s, state)
			return
		}

		code = q.Get("code")
		if code == "" {
			errC <- errors.New("no code received")
			return
		}

		// Code is valid, respond with a redirect if provided.
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	})

	if localPort == 0 {
		localPort = DefaultPort
	}

	// Setup server on the local machine using the provided port number.
	// The server will use the default handler mux.
	server := &http.Server{
		Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)),
	}

	// Start a go routine to shutdown the local callback server when the flow is complete.
	go func() {
		// Block until the flow is complete.
		<-shutdown

		if err := server.Shutdown(ctx); err != nil {
			errC <- fmt.Errorf("failed to shutdown server: %w", err)
		}
	}()

	// Open the user's browser to auth code URL as defined by their OAuth config.
	if err := browser.OpenURL(url); err != nil {
		return nil, fmt.Errorf("could not open browser for auth: %w", err)
	}

	// Start the callback server.
	// This will block until it's shutdown.
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return nil, err
	}

	// Check for handler errors.
	if len(errC) > 0 {
		return nil, <-errC
	}

	// Exchange the code for an OAuth2 token.
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("could not exchange for token: %w", err)
	}

	return token, nil
}
