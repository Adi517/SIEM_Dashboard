import wmi

def get_battery_report():
    c = wmi.WMI(namespace="root\\wmi")
    
    try:
        battery_full = c.MSBatteryFullChargedCapacity()[0].FullChargedCapacity
        battery_status = c.MSBatteryStatus()[0]
        battery_static_data = c.MSBatteryStaticData()[0]

        print("🔋 Battery Report:")
        print(f"  ➤ Charging: {battery_status.Charging}")
        print(f"  ➤ Discharging: {battery_status.Discharging}")
        print(f"  ➤ Power Online: {battery_status.PowerOnline}")
        print(f"  ➤ Estimated Charge Remaining: {battery_status.RemainingCapacity}%")
        print(f"  ➤ Cycle Count: {battery_static_data.CycleCount}")
        print(f"  ➤ Designed Capacity: {battery_static_data.DesignedCapacity}")
        print(f"  ➤ Full Charged Capacity: {battery_full}")
        
    except IndexError:
        print("Battery info not available via WMI.")

get_battery_report()
