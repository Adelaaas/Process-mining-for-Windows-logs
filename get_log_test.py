from lxml import etree
import Evtx.Evtx as evtx
import Evtx.Views as e_views


# Function to parse Sysmon events into csv format
def processSysmon(args):
    with evtx.Evtx(args.evtx) as log:
        for record in log.records():
            root = etree.fromstring(record.xml())

            # Process Create events
            if root[0][1].text == "1":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text  # UTC Time
                process_guid        = root[1][1].text  # Process GUID
                process_id          = root[1][2].text  # Process ID
                image               = root[1][3].text  # Image
                command_line        = root[1][4].text  # Command Line
                current_directory   = root[1][5].text  # Current Directory
                user                = root[1][6].text  # User
                logon_guid          = root[1][7].text  # LogonGuid
                logon_id            = root[1][8].text  # LogonId
                terminal_session_id = root[1][9].text  # TerminalSessionId
                integrity_level     = root[1][10].text  # IntegrityLevel
                hashes              = root[1][11].text  # Hashes
                parent_process_guid = root[1][12].text  # ParentProcessGuid
                parent_process_id   = root[1][13].text  # ParentProcessId
                parent_image        = root[1][14].text  # ParentImage
                parent_command_line = root[1][15].text  # ParentCommandLine

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",pguid="  + process_guid
                    + ",pid=" + process_id
                    + ",image=" + image
                    + ",cli=" + command_line
                    + ",dir=" + current_directory
                    + ",user=" + user
                    + ",logonguid=" + logon_guid
                    + ",logonid=" + logon_id
                    + ",terminalsession=" + terminal_session_id
                    + ",integrity=" + integrity_level
                    + "," + hashes
                    + ",ppguid=" + parent_process_guid
                    + ",ppid=" + parent_process_id
                    + ",pimage=" + parent_image
                    + ",pcli=" + parent_command_line
                )

            # Network events
            elif root[0][1].text == "3":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text  # UTC Time
                process_guid        = root[1][1].text
                process_id          = root[1][2].text
                image               = root[1][3].text
                user                = root[1][6].text
                protocol            = root[1][7].text
                initiated           = root[1][8].text
                source_is_ipv6      = root[1][9].text
                source_ip           = root[1][10].text
                source_hostname     = root[1][11].text
                source_port         = root[1][12].text
                source_port_name    = root[1][13].text
                dest_is_ipv6        = root[1][14].text
                dest_ip             = root[1][15].text
                dest_hostname       = root[1][16].text
                dest_port           = root[1][17].text
                dest_port_name      = root[1][18].text

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",pguid="  + process_guid
                    + ",pid=" + process_id
                    + ",image=" + image
                    + ",user=" + user
                    + ",protocol=" + protocol
                    + ",init=" + initiated
                    + ",src_hostname=" + source_hostname
                    + ",src_ip=" + source_ip
                    + ",src_port=" + source_port
                    + ",src_port_name=" + source_port_name
                    + ",dest_hostname=" + dest_hostname
                    + ",dest_ip=" + dest_ip
                    + ",dest_port=" + dest_port
                    + ",dest_port_name=" + dest_port_name
                )

            # Sysmon Service State Change
            elif root[0][1].text == "4":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text  # UTC Time
                state               = root[1][1].text
                schema_version      = root[1][2].text

                out_line = (
                    time_in_utc
                    + "," + event_id
                    + ",state=" + state
                    + ",schema=" + schema_version
                )

            # Process end event
            elif root[0][1].text == "5":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text  # UTC Time
                process_guid        = root[1][1].text  # Process GUID
                process_id          = root[1][2].text  # Process ID
                image               = root[1][3].text  # Image

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",pguid="  + process_guid
                    + ",pid=" + process_id
                    + ",image=" + image
            	)

            # Driver load events
            elif root[0][1].text == "6":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text  # UTC Time
                image_loaded        = root[1][1].text  # ImageLoaded
                hashes              = root[1][2].text  # Hashes
                signed              = root[1][3].text  # isSigned
                signiture           = root[1][4].text  # Signiture

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",driver=" + image_loaded
                    + "," + hashes
                    + ",signed=" + signed
                    + ",signiture=" + signiture
                )

            # File create events
            elif root[0][1].text == "11":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text  # UTC Time
                process_guid        = root[1][1].text  # Process GUID
                process_id          = root[1][2].text  # Process ID
                image               = root[1][3].text  # Image
                target_filename     = root[1][4].text
                creation_time_utc   = root[1][5].text

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",pguid="  + process_guid
                    + ",pid=" + process_id
                    + ",image=" + image
                    + ",filename=" + target_filename
                    + ",creationUTC=" + creation_time_utc
	            )

            # RegistryEvent - Registry object added or deleted
            elif root[0][1].text == "12":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                event_type          = root[1][0].text  # Registry event type
                time_in_utc         = root[1][1].text  # UTC Time
                process_guid        = root[1][2].text  # Process GUID
                process_id          = root[1][3].text  # Process ID
                image               = root[1][4].text  # Image
                target_object       = root[1][5].text  # Target object

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",pguid="  + process_guid
                    + ",pid=" + process_id
                    + ",image=" + image
                    + ",type=" + event_type
                    + ",object=" + target_object
	            )

            # RegistryEvent - Registry value set
            elif root[0][1].text == "13":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                event_type          = root[1][0].text  # Registry event type
                time_in_utc         = root[1][1].text  # UTC Time
                process_guid        = root[1][2].text  # Process GUID
                process_id          = root[1][3].text  # Process ID
                image               = root[1][4].text  # Image
                target_object       = root[1][5].text
                details             = root[1][5].text

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",pguid=" + process_guid
                    + ",pid=" + process_id
                    + ",image=" + image
                    + ",type=" + event_type
                    + ",object=" + target_object
                    + ",details=" + details
    	        )

            elif root[0][1].text == "16":
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text
                configuration       = root[1][1].text
                config_file_hash    = str(root[1][2].text)

                out_line = (
                    time_in_utc
                    + ",eid=" + event_id
                    + ",config=" + configuration
                    + "," + config_file_hash
        	    )

            else:
                event_id            = root[0][1].text  # EventID
                event_record_id     = root[0][8].text  # EventRecordID
                hostname            = root[0][12].text  # hostname
                time_in_utc         = root[1][0].text  # UTC Time

                out_line = (
                    "NonParsed - sysmon updated? " + time_in_utc
                    + "," + event_id + "," + event_record_id + "," + hostname
	            )

            print out_line


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Parse a Sysmon EVTX file into csv for analysis")
    parser.add_argument("evtx", type=str,
        help="Path to the Sysmon EVTX event log file")
    args = parser.parse_args()

    processSysmon(args)

if __name__ == "__main__":
    main()