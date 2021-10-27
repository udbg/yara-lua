
add_rules("mode.debug", "mode.release")
add_requires("lua 5.4", {configs = {shared = true}})

target 'yara'
    -- set kind
    set_kind 'shared'
    add_packages('lua')

    add_includedirs 'yara/libyara'
    add_includedirs 'yara/libyara/include'

    add_files("src/yara.cpp")
    add_files("yara/libyara/*.c")
    add_files("yara/libyara/modules/pe/*.c")
    add_files("yara/libyara/modules/elf/*.c")
    add_files("yara/libyara/modules/math/*.c")
    add_files("yara/libyara/modules/time/*.c")
    add_files("yara/libyara/modules/tests/*.c")

    if is_os 'windows' then
        add_defines('USE_WINDOWS_PROC')
        add_files("yara/libyara/proc/windows.c")
        add_links('advapi32')
    end