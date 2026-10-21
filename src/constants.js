module.exports = {
    MESSAGES: {
        // Requests
        PING: 0,
        REQUEST_PUBKEY: 1,
        SESSION_INIT_STAGE1: 2,
        SESSION_INIT_STAGE2: 3,
        SESSION_VERFITY_CHALLENGE: 4,
        ANOUNCE: 5,
        QUERY: 6,

        // Responses
        HELLO: 1_000_000 + 0,
        ACKNOWLEDGED: 1_000_000 + 1,
        PONG: 1_000_000 + 2,
        PUBKEY: 1_000_000 + 3,
        SESSION_INIT_STAGE1_RESPONSE: 1_000_000 + 4,
        SESSION_INFO: 1_000_000 + 5,
        SESSION_INVALID: 1_000_000 + 6,
        SESSION_VERFITY_CHALLENGE_RESPONSE: 1_000_000 + 7,
        QUERY_REFUSED: 1_000_000 + 8,
        QUERY_SUCCESS: 1_000_000 + 9,
        QUERY_FAILURE: 1_000_000 + 10
    }
}