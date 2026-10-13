package com.packetviper.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EventsUrlTest {
    @Test fun lanLink() =
        assertEquals("http://192.168.1.5:7373/api/events?t=abc", eventsUrl(" http://192.168.1.5:7373/?t=abc "))

    @Test fun relayLink() {
        assertEquals("https://relay.example.com/r/deadbeef/events", eventsUrl("https://relay.example.com/r/deadbeef"))
        assertEquals("https://relay.example.com/r/deadbeef/events", eventsUrl("https://relay.example.com/r/deadbeef/"))
    }

    @Test fun rejectsJunk() {
        assertNull(eventsUrl(""))
        assertNull(eventsUrl("http://192.168.1.5:7373/")) // LAN link without token
        assertNull(eventsUrl("ftp://host/r/x"))
        assertNull(eventsUrl("not a url"))
        assertNull(eventsUrl("https://shop.example/?ref=abc")) // stray QR with a query but no token
        assertNull(eventsUrl("https://shop.example/menu?t=1")) // token-like query on another path
        assertNull(eventsUrl("https://shop.example/r/summer-sale"))
        assertNull(eventsUrl("http://192.168.1.5:7373/?t="))
    }
}
