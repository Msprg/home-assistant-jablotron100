#!/usr/bin/env python3
"""
Development test script for Jablotron integration.
This script allows testing the integration outside of Home Assistant.
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Add the custom_components directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "custom_components"))

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import the Jablotron integration
from custom_components.jablotron100.jablotron import Jablotron
from custom_components.jablotron100.const import *
from homeassistant.const import CONF_PASSWORD

class MockHomeAssistant:
    """Mock Home Assistant instance for testing"""
    
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.bus = MockEventBus()
        self.config_entries = MockConfigEntries()
        self.helpers = MockHelpers()
        self.data = {}  # Add missing data attribute
        self.config = MockConfig()  # Add missing config attribute
        self.state = MockCoreState()  # Add missing state attribute
    
    async def async_add_executor_job(self, func, *args):
        """Mock executor job"""
        return func(*args)

class MockCoreState:
    """Mock core state"""
    
    def __init__(self):
        self.stopping = False

class MockConfig:
    """Mock config"""
    
    def __init__(self):
        self.config_dir = "/tmp/ha_test_config"
    
    def path(self, *args):
        """Mock path method"""
        import os
        return os.path.join(self.config_dir, *args)

class MockEventBus:
    """Mock event bus"""
    
    def __init__(self):
        self.listeners = {}
    
    def async_listen(self, event_type, callback):
        """Mock event listener"""
        if event_type not in self.listeners:
            self.listeners[event_type] = []
        self.listeners[event_type].append(callback)
        return lambda: None  # Return unsubscribe function
    
    def async_listen_once(self, event_type, callback):
        """Mock event listener once"""
        # For testing purposes, just call the callback immediately
        if asyncio.iscoroutinefunction(callback):
            asyncio.create_task(callback(None))
        else:
            callback(None)
        return lambda: None  # Return unsubscribe function
    
    def fire(self, event_type, data=None):
        """Mock fire event"""
        print(f"Event fired: {event_type}")
        if event_type in self.listeners:
            for callback in self.listeners[event_type]:
                callback(data)

class MockConfigEntries:
    """Mock config entries"""
    
    def __init__(self):
        self.entries = {}
    
    async def async_forward_entry_setups(self, config_entry, platforms):
        """Mock forward entry setups"""
        print(f"Forwarding entry setups for platforms: {platforms}")
    
    async def async_unload_platforms(self, config_entry, platforms):
        """Mock unload platforms"""
        print(f"Unloading platforms: {platforms}")
    
    async def async_reload(self, entry_id):
        """Mock reload"""
        print(f"Reloading entry: {entry_id}")

class MockHelpers:
    """Mock helpers"""
    
    def __init__(self):
        self.device_registry = MockDeviceRegistry()
        self.entity_registry = MockEntityRegistry()
        self.storage = MockStorage()

class MockDeviceRegistry:
    """Mock device registry"""
    
    def __init__(self):
        self.devices = {}
    
    def async_get_or_create(self, **kwargs):
        """Mock device creation"""
        print(f"Creating device: {kwargs}")
        return MockDevice()
    
    def async_get_device(self, identifiers):
        """Mock get device"""
        return None
    
    def async_remove_device(self, device_id):
        """Mock remove device"""
        print(f"Removing device: {device_id}")

class MockEntityRegistry:
    """Mock entity registry"""
    
    def __init__(self):
        self.entities = {}
    
    def async_remove(self, entity_id):
        """Mock remove entity"""
        print(f"Removing entity: {entity_id}")

class MockStorage:
    """Mock storage"""
    
    def __init__(self):
        self.data = {}
    
    async def async_load(self):
        """Mock load storage"""
        return self.data
    
    async def async_delay_save(self, data_func):
        """Mock delay save"""
        self.data = data_func()

class MockDevice:
    """Mock device"""
    
    def __init__(self):
        self.id = "mock_device_id"

class MockConfigEntry:
    """Mock config entry"""
    
    def __init__(self, data, options):
        self.entry_id = "test_entry"
        self.data = data
        self.options = options
        self.runtime_data = None
    
    def add_update_listener(self, callback):
        """Mock update listener"""
        return lambda: None  # Return unsubscribe function
    
    def async_on_unload(self, callback):
        """Mock on unload"""
        pass

async def test_jablotron_integration():
    """Test the Jablotron integration"""
    
    print("Starting Jablotron integration test...")
    
    # Create mock Home Assistant instance
    hass = MockHomeAssistant()
    
    # Load configuration from separate file
    try:
        from test_config import CONFIG_DATA, OPTIONS
        
        # Convert config data to use Home Assistant constants
        config_data = {
            CONF_SERIAL_PORT: CONFIG_DATA["serial_port"],
            CONF_PASSWORD: CONFIG_DATA["password"],
            CONF_NUMBER_OF_DEVICES: CONFIG_DATA["number_of_devices"],
            CONF_NUMBER_OF_PG_OUTPUTS: CONFIG_DATA["number_of_pg_outputs"],
            CONF_UNIQUE_ID: CONFIG_DATA["unique_id"]
        }
        
        # Convert options to use Home Assistant constants
        options = {
            CONF_ENABLE_DEBUGGING: OPTIONS["enable_debugging"],
            CONF_LOG_ALL_INCOMING_PACKETS: OPTIONS["log_all_incoming_packets"],
            CONF_LOG_ALL_OUTCOMING_PACKETS: OPTIONS["log_all_outcoming_packets"],
            CONF_REQUIRE_CODE_TO_ARM: OPTIONS["require_code_to_arm"],
            CONF_REQUIRE_CODE_TO_DISARM: OPTIONS["require_code_to_disarm"],
            CONF_PARTIALLY_ARMING_MODE: PartiallyArmingMode.NIGHT_MODE.value if OPTIONS["partially_arming_mode"] == "night_mode" else PartiallyArmingMode.HOME_MODE.value
        }
        
    except ImportError:
        print("ERROR: test_config.py not found!")
        print("Please create test_config.py with your configuration data.")
        print("See the example in test_config.py.example")
        return
    
    # Create mock config entry
    config_entry = MockConfigEntry(config_data, options)
    
    try:
        # Create Jablotron instance
        jablotron = Jablotron(hass, config_entry.entry_id, config_data, options)
        
        print("Initializing Jablotron...")
        await jablotron.initialize()
        
        print("Jablotron initialized successfully!")
        print(f"Central unit: {jablotron.central_unit()}")
        print(f"Last update success: {jablotron.last_update_success}")
        
        # Test basic functionality
        print("\nTesting basic functionality...")
        
        # Test serial port detection
        detected_port = await jablotron._detect_serial_port()
        print(f"Detected serial port: {detected_port}")

        print("is logged into jablotron?" + str(jablotron._successful_login))
        
        # Keep running for a short time to see if we get any data
        print("Running for 10 seconds to test communication...")
        await asyncio.sleep(10)
        
        print("Test completed successfully!")
        
    except Exception as e:
        print(f"Error during test: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        if 'jablotron' in locals():
            jablotron.shutdown()

if __name__ == "__main__":
    print("Jablotron Integration Development Test")
    print("=====================================")
    print()
    print("This script tests the Jablotron integration outside of Home Assistant.")
    print("Make sure your Jablotron device is connected via USB.")
    print()
    
    # Check if we're running in the virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✓ Running in virtual environment")
    else:
        print("⚠ Not running in virtual environment")
    
    # Run the test
    asyncio.run(test_jablotron_integration())
