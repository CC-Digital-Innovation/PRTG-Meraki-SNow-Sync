from src.prtg_meraki_snow_sync import get_clover_mac
from src.prtg_meraki_snow_sync import get_window_number


def test_get_clover_mac():
    # Test typical device names.
    assert get_clover_mac('[SiteName123] Window 01 d4:95:24:00:00:00') == 'd4:95:24:00:00:00'
    assert get_clover_mac('[SiteName123] Window 01 74:d4:dd:00:00:00') == '74:d4:dd:00:00:00'
    assert get_clover_mac('d4:95:24:00:00:00') == 'd4:95:24:00:00:00'
    assert get_clover_mac('74:d4:dd:00:00:00') == '74:d4:dd:00:00:00'
    
    # Test invalid device names with valid MAC addresses.
    assert get_clover_mac('jkaldugbiopga d4:95:24:00:00:00') == 'd4:95:24:00:00:00'
    assert get_clover_mac('jhgrkoehbanguiore 74:d4:dd:00:00:00') == '74:d4:dd:00:00:00'
    assert get_clover_mac('jkaldugbiopgad4:95:24:00:00:00') == 'd4:95:24:00:00:00'
    assert get_clover_mac('jhgrkoehbanguiore74:d4:dd:00:00:00') == '74:d4:dd:00:00:00'
    
    # Test device names with extra spaces.
    assert get_clover_mac('[SiteName123] Window 01 d4:95:24:00:00:00 ') == 'd4:95:24:00:00:00'
    assert get_clover_mac('[SiteName123] Window 01 74:d4:dd:00:00:00   ') == '74:d4:dd:00:00:00'
    
    # Test device names with dashes.
    assert get_clover_mac('[SiteName123] Window 01 d4-95-24-00-00-00 ') == 'd4:95:24:00:00:00'
    assert get_clover_mac('[SiteName123] Window 01 74-d4-dd-00-00-00 ') == '74:d4:dd:00:00:00'
    
    # Test device names with double colons.
    assert get_clover_mac('[SiteName123] Window 01 d4:95:24:00::00:00 ') == 'd4:95:24:00:00:00'
    assert get_clover_mac('[SiteName123] Window 01 74:d4::dd:00:00:00 ') == '74:d4:dd:00:00:00'
    
    # Test invalid MAC addresses.
    assert get_clover_mac('[SiteName123] Window 01 d4:95f:24:00::00:00 ') == ''
    assert get_clover_mac('[SiteName123] Window 01 74:d4::dd:00:s00:00 ') == ''
    
    # Test device names with non-Clover MAC addresses.
    assert get_clover_mac('[SiteName123] Window 01 d4:9f:24:00:00:00') == ''
    assert get_clover_mac('[SiteName123] Window 01 74:d5:dd:00:00:00') == ''
    assert get_clover_mac('[SiteName123] Window 01 00:00:00:00:00:00') == ''
    
    # Test device names with invalid characters in the MAC addresses.
    assert get_clover_mac('[SiteName123] Window 01 d4:95:24:gg:00:00') == ''
    assert get_clover_mac('[SiteName123] Window 01 74:d5:dd:00:hh:00') == ''
    
    # Test device names with invalid formats.
    assert get_clover_mac('uerwoipahguioreh') == ''
    assert get_clover_mac('') == ''
    assert get_clover_mac('4879hguffhg74h379th84390hg789re') == ''


def test_get_window_number():
    # Test typical device names in PRTG.
    assert get_window_number('[SiteName123] Window 39 d4:95:24:00:00:00') == '39'
    assert get_window_number('[SiteName123] Window 12A d4:95:24:00:00:00') == '12A'
    assert get_window_number('[SiteName123] Window CC1 d4:95:24:00:00:00') == 'CC1'
    assert get_window_number('[SiteName123] Window MGR1 74:d4:dd:00:00:00') == 'MGR1'
    assert get_window_number('[SiteName123] Window INFO1 74:d4:dd:00:00:00') == 'INFO1'

    # Test typical device names in Meraki.
    assert get_window_number('Window 39 d4:95:24:00:00:00') == '39'
    assert get_window_number('Window 12A d4:95:24:00:00:00') == '12A'
    assert get_window_number('Window CC1 d4:95:24:00:00:00') == 'CC1'
    assert get_window_number('Window MGR1 74:d4:dd:00:00:00') == 'MGR1'
    assert get_window_number('Window INFO1 74:d4:dd:00:00:00') == 'INFO1'
    
    # Test backup devices in Meraki.
    assert get_window_number('Backup d4:95:24:00:00:00') is None
    assert get_window_number('backup d4:95:24:00:00:00') is None
    assert get_window_number('backupd4:95:24:00:00:00') is None
    assert get_window_number('Backup 74:d4:dd:00:00:00') is None
    assert get_window_number('Backup74:d4:dd:00:00:00') is None
    assert get_window_number('bacup74:d4:dd:00:00:00') is None

    # Test device names with missing spaces.
    assert get_window_number('[SiteName123] Window 01d4:95:24:00:00:00') == '01'
    assert get_window_number('[SiteName123] WindowCC1 74:d4:dd:00:00:00') == 'CC1'
    assert get_window_number('[SiteName123]Window 12B d4:95:24:00:00:00') == '12B'
    assert get_window_number('[SiteName123]WindowMGR4 74:d4:dd:00:00:00') == 'MGR4'
    assert get_window_number('[SiteName123] WindowINFO174:d4:dd:00:00:00') == 'INFO1'
    assert get_window_number('[SiteName123]Window 1174:d4:dd:00:00:00') == '11'
    assert get_window_number('[SiteName123]Window9974:d4:dd:00:00:00') == '99'
    
    # Test device names with extra spaces.
    assert get_window_number('[SiteName123] Window 01 d4:95:24:00:00:00 ') == '01'
    assert get_window_number('[SiteName123] Window 12A 74:d4:dd:00:00:00   ') == '12A'
    assert get_window_number('[SiteName123]   Window CC3 d4:95:24:00:00:00 ') == 'CC3'
    assert get_window_number('[SiteName123] Window   MGR6 74:d4:dd:00:00:00') == 'MGR6'
    assert get_window_number('[SiteName123] Window   INFO2   d4:95:24:00:00:00 ') == 'INFO2'
    assert get_window_number('    [SiteName123]     Window     01    74:d4:dd:00:00:00    ') == '01'
    assert get_window_number('    [SiteName123] Window 02 d4:95:24:00:00:00') == '02'
    assert get_window_number('  [SiteName123]  Window 10    74:d4:dd:00:00:00    ') == '10'
    
    # Test device names with dashes.
    assert get_window_number('[SiteName123] Window 01 d4-95-24-00-00-00') == '01'
    assert get_window_number('[SiteName123] Window 99 74-d4-dd-00-00-00') == '99'
    
    # Test device names with invalid formats.
    assert get_window_number('uerwoipahguioreh') is None
    assert get_window_number('') is None
    assert get_window_number('4') is None
    assert get_window_number('f') is None
    assert get_window_number('d4-95-24-00-00-00') is None
    assert get_window_number('74-d4-dd-00-00-00') is None
    assert get_window_number('[SiteName123] Window NONSENSE d4:95:24:00:00:00') is None
    assert get_window_number('[SiteName123] Window ??? huh? 74:d4:dd:00:00:00') is None
