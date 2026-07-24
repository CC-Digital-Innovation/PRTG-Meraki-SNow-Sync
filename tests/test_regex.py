from src.prtg_meraki_snow_sync import CLOVER_WINDOW_NUMBER_REGEX
from src.prtg_meraki_snow_sync import CLOVER_SERIAL_NUMBER_LONG_REGEX
from src.prtg_meraki_snow_sync import CLOVER_SERIAL_NUMBER_SHORT_REGEX
from src.prtg_meraki_snow_sync import CLOVER_MAC_ADDRESS_REGEX

from src.prtg_meraki_snow_sync import MERAKI_CLOVER_NAME_REGEX
from src.prtg_meraki_snow_sync import MERAKI_SITE_INFO_REGEX

from src.prtg_meraki_snow_sync import PRTG_CLOVER_NAME_REGEX
from src.prtg_meraki_snow_sync import PRTG_SITE_IN_CLOVER_NAME_REGEX
from src.prtg_meraki_snow_sync import PRTG_SITE_INFO_REGEX


def test_clover_window_number_regex():
    # Test numbered windows.
    assert CLOVER_WINDOW_NUMBER_REGEX.match('01') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('11') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('00') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('99') is not None
    
    # Test invalid window numbers.
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('0') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('000') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('111') is None

    # Test 2-character windows with / without numbers.
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CC1') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CC9') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CC00') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CC10') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CC100') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cc1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cc11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cc111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('Cc1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('Cc11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('Cc111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cC1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cC11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cC111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cc') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CC') is None
    
    # Test 3-character windows with / without numbers.
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCC1') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCC9') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCC00') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCC10') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCC100') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('ccc1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('ccc11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('ccc111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCC1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCC11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCC111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CcC1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CcC11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CcC111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCc1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCc11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCc111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCC') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('ccc') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCC') is None

    # Test 4-character windows with / without numbers.
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCC1') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCC9') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCC00') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCC10') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCC100') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cccc1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cccc11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cccc111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCCC1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCCC11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCCC111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CcCC1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CcCC11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CcCC111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCcC1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCcC11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCcC111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCc1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCc11') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCc111') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('CCCC') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cccc') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('cCCC') is None
    
    # Test window numbers with a single letter suffix.
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1A') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1B') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1Z') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('10A') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('10B') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('10Z') is not None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1a') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1b') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1z') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('10a') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('10b') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('10z') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('100A') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('100B') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('100Z') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('100a') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('100b') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('100z') is None

    # Test invalid window numbers.
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1AA') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1BB') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1ZZ') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('B1BB') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('B1B') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('1') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('   12') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('   12    ') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('12    ') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('    ') is None
    assert CLOVER_WINDOW_NUMBER_REGEX.match('') is None


def test_clover_serial_number_long_regex():
    # Test valid long serial numbers.
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('Clover A123B C456DE78901234') is not None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('Clover Z999Y Z000XY12345678') is not None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('Clover M001N M002MN00000000') is not None
    
    # Test invalid long serial numbers.
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('clover A123B C456DE78901234') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('clover Z999YZ000XY12345678') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('cloverM001N M002MN00000000') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('cloverM001NM002MN00000000') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('Clover a123b c456de78901234') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('Clover z999y z000xy12345678') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('Clover m001n m002mn00000000') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('clover m001n m002mn00000000') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('a123b c456de78901234') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('Clov z999y z000xy12345678') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('m001n m002m n00000000') is None
    assert CLOVER_SERIAL_NUMBER_LONG_REGEX.match('over m001n m002mn00000000') is None


def test_clover_serial_number_short_regex():
    # Test valid short serial numbers.
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('C456DE78901234') is not None
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('Z000XY12345678') is not None
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('M002MN00000000') is not None
    
    # Test invalid short serial numbers.
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('c456de78901234') is None
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('z000xy12345678') is None
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('m002mn00000000') is None
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('c456de7890123') is None
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('z000xy1234567') is None
    assert CLOVER_SERIAL_NUMBER_SHORT_REGEX.match('m002mn0000000') is None


def test_clover_mac_address_regex():
    # Test : MAC addresses.
    assert CLOVER_MAC_ADDRESS_REGEX.match('d4:95:24:12:34:56') is not None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74:d4:dd:65:43:21') is not None
    assert CLOVER_MAC_ADDRESS_REGEX.match('D4:95:24:12:34:56') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74:D4:DD:65:43:21') is None
    
    # Test - MAC addresses.
    assert CLOVER_MAC_ADDRESS_REGEX.match('d4-95-24-12-34-56') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74-d4-dd-65-43-21') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('D4-95-24-12-34-56') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74-D4-DD-65-43-21') is None
    
    # Test non-Clover MAC addresses.
    assert CLOVER_MAC_ADDRESS_REGEX.match('00:1A:2B:3C:4D:5E') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('00:1a:2b:3c:4d:5e') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('00-1A-2B-3C-4D-5E') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('00-1a-2b-3c-4d-5e') is None
    
    # Test invalid MAC addresses.
    assert CLOVER_MAC_ADDRESS_REGEX.match('d4:95:24:12:34:12:34') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('d4:95:24:gg:gg:56') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74:d4:dd:65:43:12:34:12:34') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74:d4:dd:65:43:gg') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('D4:95:24:12:') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74:D4:DD:65') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('d4-95-24-12-') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74-d4-dd-65-43') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('D4-95-24-1234') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('74-D4-DD-65-4') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('00:1:2B:3C:4D:5') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match(':1a:2b:3c:4d:5e') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('00-1A-2B-34D-5E') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('-1a-2b-3c-4d-') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('-1a-2b-3c-4d:') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('1a-2b-3c-4d:11') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('00:1A:2B:3C:4D:5E:') is None
    assert CLOVER_MAC_ADDRESS_REGEX.match('00:1A:2B:3C:4D:5E-') is None


def test_meraki_clover_name_regex():
    # Test valid Meraki Clover names.
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 01 d4:95:24:12:34:56') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 01 74:d4:dd:65:43:21') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window CC1 74:d4:dd:65:43:21') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window CC1 d4:95:24:12:34:56') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window SH1 74:d4:dd:65:43:21') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window SH1 d4:95:24:12:34:56') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window MGR1 74:d4:dd:65:43:21') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window MGR1 d4:95:24:12:34:56') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window INFO1 74:d4:dd:65:43:21') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window INFO1 d4:95:24:12:34:56') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 12A d4:95:24:12:34:56') is not None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 12B 74:d4:dd:65:43:21') is not None

    # Test invalid Meraki Clover names.
    assert MERAKI_CLOVER_NAME_REGEX.match('window 01 d4:95:24:12:34:56') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('window 01 74:d4:dd:65:43:21') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('widow 01 d4:95:24:12:34:56') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('widow 01 74:d4:dd:65:43:21') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 011 d4:95:24:12:34:56') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 011 74:d4:dd:65:43:21') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 11A d3:95:24:12:34:56') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 11B 75:d4:dd:65:43:21') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 11Af d4:95:24:12:34:56') is None
    assert MERAKI_CLOVER_NAME_REGEX.match('Window 11Bf 74:d4:dd:65:43:21') is None
    
    
def test_meraki_site_info_regex():
    # Test valid Meraki site info.
    assert MERAKI_SITE_INFO_REGEX.match('(Site Info)') is not None
    assert MERAKI_SITE_INFO_REGEX.match('(Site Info 123)') is not None
    assert MERAKI_SITE_INFO_REGEX.match('(Site Info ABC)') is not None
    assert MERAKI_SITE_INFO_REGEX.match('(Site Info 123 ABC)') is not None
    assert MERAKI_SITE_INFO_REGEX.match('(Site Info 123 ABC 456)') is not None
    assert MERAKI_SITE_INFO_REGEX.match('(1)') is not None
    assert MERAKI_SITE_INFO_REGEX.match('(2)') is not None
    assert MERAKI_SITE_INFO_REGEX.match('(99)') is not None

    # Test invalid Meraki site info.
    assert MERAKI_SITE_INFO_REGEX.match('Site Info') is None
    assert MERAKI_SITE_INFO_REGEX.match('Site Info 123') is None
    assert MERAKI_SITE_INFO_REGEX.match('Site Info ABC') is None
    assert MERAKI_SITE_INFO_REGEX.match('Site Info 123 ABC') is None
    assert MERAKI_SITE_INFO_REGEX.match('Site Info 123 ABC 456') is None
    assert MERAKI_SITE_INFO_REGEX.match('1') is None
    assert MERAKI_SITE_INFO_REGEX.match('(1') is None
    assert MERAKI_SITE_INFO_REGEX.match('1)') is None


def test_prtg_clover_name_regex():
    # Test valid PRTG Clover names.
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 d4:95:24:12:34:56') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[Site456] Window 01 74:d4:dd:65:43:21') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[E789] Window CC1 74:d4:dd:65:43:21') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[e789] Window CC1 74:d4:dd:65:43:21') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName012] Window CC1 d4:95:24:12:34:56') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName345] Window SH1 74:d4:dd:65:43:21') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName678] Window SH1 d4:95:24:12:34:56') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName901] Window MGR1 74:d4:dd:65:43:21') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName234] Window MGR1 d4:95:24:12:34:56') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName567] Window INFO1 74:d4:dd:65:43:21') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName890] Window INFO1 d4:95:24:12:34:56') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 12A d4:95:24:12:34:56') is not None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName456] Window 12B 74:d4:dd:65:43:21') is not None
    
    # Test invalid site names.
    assert PRTG_CLOVER_NAME_REGEX.match('SiteName123] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123 Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123]Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[a] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[1] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[123] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[edsfa] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[edsfa1] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[edsfa12] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[edsfa1234] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName1234] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[123SiteName] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[1234SiteName123] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[1SiteName123] Window 01 d4:95:24:12:34:56') is None
    
    # Test invalid window names.
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Widnow 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123]Window 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123]Window01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] WINDOW 01 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] 01 Window d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] 01 d4:95:24:12:34:56') is None
    
    # Test invalid window numbers.
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 011 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 1 d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 11AA d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window B11B d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window B1B d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window kgsad d4:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 8567 d4:95:24:12:34:56') is None
    
    # Test invalid MAC addresses.
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 d4:95:24:12:34:12:34') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 d4:95:24:gg:gg:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 74:d4:dd:65:43:12:34:12:34') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 74:d4:dd:65:43:gg') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 D4:95:24:12:') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 74:D4:DD:65') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 d4-95-24-12-') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 74-d4-dd-65-43') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 D4-95-24-1234') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 74-D4-DD-65-4') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 00:1:2B:3C:4D:5') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 :1a:2b:3c:4d:5e') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 00-1A-2B-34D-5E') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 -1a-2b-3c-4d-') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 -1a-2b-3c-4d:') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 1a-2b-3c-4d:11') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 00:1A:2B:3C:4D:5E:') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 00:1A:2B:3C:4D:5E-') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 dc:95:24:12:34:56') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 hgrea:gruioew') is None
    assert PRTG_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 garah') is None


def test_prtg_site_in_clover_name_regex():
    # Test valid PRTG site info in Clover names.
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName123] Window 01 d4:95:24:12:34:56') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[Site456] Window 01 74:d4:dd:65:43:21') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[E789] Window CC1 74:d4:dd:65:43:21') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[e789] Window CC1 74:d4:dd:65:43:21') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName012] Window CC1 d4:95:24:12:34:56') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName345] Window SH1 74:d4:dd:65:43:21') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName678] Window SH1 d4:95:24:12:34:56') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName901] Window MGR1 74:d4:dd:65:43:21') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName234] Window MGR1 d4:95:24:12:34:56') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName567] Window INFO1 74:d4:dd:65:43:21') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName890] Window INFO1 d4:95:24:12:34:56') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName123] Window 12A d4:95:24:12:34:56') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName456] Window 12B 74:d4:dd:65:43:21') is not None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName123]Window 01 d4:95:24:12:34:56') is not None
    
    # Test invalid PRTG site info in Clover names.
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('SiteName123] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName123 Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[a] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[1] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[123] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[edsfa] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[edsfa1] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[edsfa12] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[edsfa1234] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[SiteName1234] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[123SiteName] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[1234SiteName123] Window 01 d4:95:24:12:34:56') is None
    assert PRTG_SITE_IN_CLOVER_NAME_REGEX.match('[1SiteName123] Window 01 d4:95:24:12:34:56') is None


def test_prtg_site_info_regex():
    # Test valid PRTG site info.
    assert PRTG_SITE_INFO_REGEX.match(' MASTER') is not None
    assert PRTG_SITE_INFO_REGEX.match(' master') is not None
    assert PRTG_SITE_INFO_REGEX.match(' Master') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (MASTER)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (master)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (Master)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (1)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (2)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (new)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (new4362)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (LTE Only)') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (1) ') is not None
    assert PRTG_SITE_INFO_REGEX.match(' (new) ') is not None
    
    # Test invalid PRTG site info.
    assert PRTG_SITE_INFO_REGEX.match(' 1') is None
    assert PRTG_SITE_INFO_REGEX.match(' (1') is None
    assert PRTG_SITE_INFO_REGEX.match(' 1)') is None
    assert PRTG_SITE_INFO_REGEX.match(' ()') is None
    assert PRTG_SITE_INFO_REGEX.match(' () ') is None
    assert PRTG_SITE_INFO_REGEX.match('(1)') is None
    assert PRTG_SITE_INFO_REGEX.match('(new)') is None
    assert PRTG_SITE_INFO_REGEX.match('()') is None
    assert PRTG_SITE_INFO_REGEX.match('') is None
    assert PRTG_SITE_INFO_REGEX.match(' ') is None
