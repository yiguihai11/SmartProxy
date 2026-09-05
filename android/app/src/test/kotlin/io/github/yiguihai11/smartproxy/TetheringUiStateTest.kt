package io.github.yiguihai11.smartproxy

import io.github.yiguihai11.smartproxy.shizuku.ShizukuTetheringService
import io.github.yiguihai11.smartproxy.shizuku.TetheringStatusSnapshot
import io.github.yiguihai11.smartproxy.shizuku.tetheringTypeBit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TetheringUiStateTest {

    @Test
    fun failedShutdownRetainsSessionEvenWhenCoreIsStopped() {
        val state = TetheringUiState(
            serviceConnected = true,
            hasRoutingSession = true,
            routingState = ShizukuTetheringService.ROUTING_STATE_ERROR,
            coreRunning = false,
        )
        assertTrue(state.routingSessionEnabled)
        assertFalse(state.withServiceConnection(false).hasRoutingSession)
    }

    @Test
    fun hotspotStateIsDerivedFromTheActiveTetheringMask() {
        val unknown = TetheringUiState()
        assertFalse(unknown.tetheringStateKnown)
        assertFalse(unknown.hotspotEnabled)

        val disabled = TetheringUiState(activeTetheringTypes = 0)
        assertTrue(disabled.tetheringStateKnown)
        assertFalse(disabled.hotspotEnabled)

        val usbOnly = TetheringUiState(
            activeTetheringTypes = 1 shl ShizukuTetheringService.TETHERING_TYPE_USB,
        )
        assertFalse(usbOnly.hotspotEnabled)

        val wifi = TetheringUiState(
            activeTetheringTypes = 1 shl ShizukuTetheringService.TETHERING_TYPE_WIFI,
        )
        assertTrue(wifi.hotspotEnabled)
    }

    @Test
    fun uiStateStartsDisconnectedAndResetsShellStateOnDisconnect() {
        val initial = TetheringUiState()
        assertFalse(initial.serviceConnected)

        val connected = initial.withServiceConnection(true).copy(
            operation = TetheringOperation.STARTING_ROUTING,
            routingState = ShizukuTetheringService.ROUTING_STATE_ACTIVE,
            routingDetail = "testtun0 · SmartProxy",
            activeTetheringTypes = tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_WIFI),
            ipv6TetheringTypes = 0,
            coreRunning = true,
        )
        val disconnected = connected.withServiceConnection(false)

        assertFalse(disconnected.serviceConnected)
        assertEquals(TetheringOperation.NONE, disconnected.operation)
        assertEquals(ShizukuTetheringService.ROUTING_STATE_DISABLED, disconnected.routingState)
        assertEquals("", disconnected.routingDetail)
        assertEquals(ShizukuTetheringService.TETHERING_TYPES_UNKNOWN, disconnected.activeTetheringTypes)
        assertEquals(ShizukuTetheringService.TETHERING_TYPES_UNKNOWN, disconnected.ipv6TetheringTypes)
        assertTrue(disconnected.coreRunning)
    }

    @Test
    fun uiStateMapsCoreAndUserServiceSnapshots() {
        val coreRunning = TetheringUiState(coreRunning = true)
        assertTrue(coreRunning.coreRunning)

        val status = TetheringStatusSnapshot(
            routingState = ShizukuTetheringService.ROUTING_STATE_ACTIVE,
            routingDetail = "testtun4 · SmartProxy",
            activeTetheringTypes = tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_USB),
            ipv6TetheringTypes = 0,
            warning = ShizukuTetheringService.RESULT_OK,
            hasRoutingSession = true,
        )
        val loaded = coreRunning.copy(operation = TetheringOperation.CHECKING)
            .withTetheringStatus(status, ipv6Enabled = true)

        assertEquals(TetheringOperation.NONE, loaded.operation)
        assertEquals(status.routingState, loaded.routingState)
        assertEquals(status.routingDetail, loaded.routingDetail)
        assertEquals(status.activeTetheringTypes, loaded.activeTetheringTypes)
        assertEquals(status.ipv6TetheringTypes, loaded.ipv6TetheringTypes)
        assertTrue(loaded.ipv6Enabled)
        assertTrue(loaded.hasRoutingSession)
    }

    @Test
    fun reportsTheObservedIpModeForEachActiveDownstream() {
        val wifi = tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_WIFI)
        val usb = tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_USB)
        val state = TetheringUiState(
            activeTetheringTypes = wifi or usb,
            ipv6TetheringTypes = wifi,
            ipv6Enabled = true,
        )

        assertEquals(
            TetheringIpMode.DUAL_STACK,
            state.ipMode(ShizukuTetheringService.TETHERING_TYPE_WIFI),
        )
        assertEquals(
            TetheringIpMode.IPV4_ONLY,
            state.ipMode(ShizukuTetheringService.TETHERING_TYPE_USB),
        )
    }

    @Test
    fun hidesTheIpModeWhenIpv6IsDisabledOrTheDownstreamIsInactive() {
        val wifi = tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_WIFI)
        val disabled = TetheringUiState(activeTetheringTypes = wifi)
            .ipMode(ShizukuTetheringService.TETHERING_TYPE_WIFI)
        val inactive = TetheringUiState(
            activeTetheringTypes = wifi,
            ipv6TetheringTypes = wifi,
            ipv6Enabled = true,
        ).ipMode(ShizukuTetheringService.TETHERING_TYPE_USB)

        assertNull(disabled)
        assertNull(inactive)
    }

    @Test
    fun doesNotMistakeAnUnavailableIpv6ProbeForIpv4Only() {
        val wifi = tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_WIFI)
        val state = TetheringUiState(
            activeTetheringTypes = wifi,
            ipv6TetheringTypes = ShizukuTetheringService.TETHERING_TYPES_UNKNOWN,
            ipv6Enabled = true,
        )

        assertEquals(
            TetheringIpMode.UNKNOWN,
            state.ipMode(ShizukuTetheringService.TETHERING_TYPE_WIFI),
        )
    }
}
