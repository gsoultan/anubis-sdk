package io.github.gsoultan.anubis;

import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Holds a token pair and keeps it fresh. Thread-safe, and that is the entire
 * reason it exists.
 *
 * <p>Refresh tokens are single-use and rotate on every refresh. Two threads
 * that both notice an expired access token will both refresh; one wins, and the
 * other presents a token Anubis has already consumed. Anubis reads that,
 * correctly, as theft — and revokes the family and the session. A client
 * without this class logs its own users out under concurrency, and pages a
 * human while doing it.
 *
 * <p>So refreshes are single-flight: the first caller refreshes, everyone else
 * waits for that same result. One refresh per rotation, always.
 */
public final class TokenSource {
    /**
     * Refresh a little before the access token actually expires. A token valid
     * when the request leaves and expired when it arrives is a 401 nobody can
     * reproduce.
     */
    private static final Duration MARGIN = Duration.ofSeconds(30);

    private final java.util.function.Function<Tokens, Tokens> refresh;
    private final Clock clock;
    private final boolean needsRefreshToken;

    private final Object lock = new Object();
    private Tokens tokens;
    private Consumer<Tokens> onRotate;
    private CompletableFuture<Tokens> inflight;

    TokenSource(
        java.util.function.Function<Tokens, Tokens> refresh,
        Tokens initial,
        Clock clock,
        boolean needsRefreshToken) {
        this.refresh = refresh;
        this.tokens = initial;
        this.clock = clock;
        this.needsRefreshToken = needsRefreshToken;
    }

    /**
     * Register a callback for every new pair.
     *
     * <p>It runs BEFORE {@link #token()} returns, so a process that dies
     * between the two has already stored the new pair. Storing afterwards loses
     * the rotation on a crash and produces the same self-inflicted theft signal
     * this class exists to prevent.
     */
    public TokenSource onRotate(Consumer<Tokens> fn) {
        synchronized (lock) {
            this.onRotate = fn;
        }
        return this;
    }

    /** The pair held right now, without refreshing. */
    public Tokens current() {
        synchronized (lock) {
            return tokens;
        }
    }

    /** A valid access token, refreshing if the one held is close to expiry. */
    public Tokens token() {
        CompletableFuture<Tokens> mine;
        CompletableFuture<Tokens> theirs = null;
        Tokens snapshot = null;
        synchronized (lock) {
            if (valid()) {
                return tokens;
            }
            if (inflight != null) {
                // Somebody is already rotating. Take a reference and wait for
                // their result OUTSIDE this block — the rotating thread needs
                // this same monitor to finish, so joining while holding it
                // would deadlock rather than merely serialise.
                theirs = inflight;
                mine = null;
            } else {
                if (needsRefreshToken
                    && (tokens == null || tokens.refreshToken() == null || tokens.refreshToken().isEmpty())) {
                    throw new AnubisException(
                        "anubis: the access token has expired and there is no refresh token — sign in again");
                }
                mine = new CompletableFuture<>();
                inflight = mine;
                snapshot = tokens;
            }
        }
        if (theirs != null) {
            return joinOutsideLock(theirs);
        }
        return rotate(mine, snapshot);
    }

    private Tokens joinOutsideLock(CompletableFuture<Tokens> theirs) {
        try {
            return theirs.join();
        } catch (java.util.concurrent.CompletionException e) {
            Throwable cause = e.getCause();
            throw cause instanceof RuntimeException re ? re : new AnubisException(e.getMessage(), e);
        }
    }

    private Tokens rotate(CompletableFuture<Tokens> mine, Tokens snapshot) {
        Tokens next;
        try {
            next = refresh.apply(snapshot);
        } catch (RuntimeException e) {
            synchronized (lock) {
                inflight = null;
            }
            mine.completeExceptionally(e);
            throw e;
        }
        Consumer<Tokens> callback;
        Tokens rotated;
        synchronized (lock) {
            // A re-mint returns no refresh token; carry the old one forward so
            // the source stays usable.
            if ((next.refreshToken() == null || next.refreshToken().isEmpty()) && snapshot != null) {
                next = new Tokens(next.accessToken(), snapshot.refreshToken(), next.tokenType(),
                    next.expiresIn(), next.sessionId(), next.issuedAt());
            }
            // Adopted before the persist callback runs: the old refresh token
            // is already dead on the server, so holding it after a failed
            // persist would guarantee a reuse refusal next time.
            tokens = next;
            rotated = next;
            callback = onRotate;
            inflight = null;
        }
        // Called outside the lock: the callback persists somewhere that may
        // itself take time, and holding the monitor across it would serialise
        // every reader behind a disk write. It still runs before token()
        // returns, which is what "before" means here.
        if (callback != null) {
            try {
                callback.accept(rotated);
            } catch (RuntimeException e) {
                mine.completeExceptionally(e);
                throw e;
            }
        }
        mine.complete(rotated);
        return rotated;
    }

    private boolean valid() {
        if (tokens == null || tokens.accessToken() == null || tokens.accessToken().isEmpty()) {
            return false;
        }
        java.time.Instant expiry = tokens.expiry();
        if (expiry == null) {
            // No expiry known: the only honest reading is that it is still
            // good, since refreshing on every call would burn a rotation per
            // request.
            return true;
        }
        return clock.instant().plus(MARGIN).isBefore(expiry);
    }
}
