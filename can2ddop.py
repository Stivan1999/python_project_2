# import libraries
import os.path
import tkinter
from tkinter import *
import customtkinter
from tkinter import filedialog
from xml.dom import minidom
import re
from ctypes import *
import struct
import subprocess


customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")


def main():

    app = customtkinter.CTk()
    app.title("can2ddop")
    app.geometry("780x520")

    # function to open file when button is pressed
    def open_file():
        global file_extension
        textArea1.delete("1.0", 'end-1c')
        # open file that needs to be converted
        file_to_open = filedialog.askopenfilename(initialdir="/C", title="Select a file",
                                                  filetypes=[("All files", "*.*")])
        # get the name of the file opened and its extension (type)
        file_name, file_extension = os.path.splitext(file_to_open)

        if file_extension == ".blf":
            with open('blf_output.txt', 'w') as f:
                subprocess.run(['BlfDump.exe', file_name + '.blf'],
                               shell=True,
                               text=True,
                               stdout=f)
            with open('blf_output.txt', 'r') as f:
                stuff = f.read()
                textArea1.insert('end-1c', stuff)
            os.remove("blf_output.txt")
        else:
            with open(file_to_open, 'r') as file:
                stuff = file.read()
                textArea1.insert('end-1c', stuff)

    # function to do the conversion
    def convert_file():
        textArea2.delete("1.0", 'end-1c')
        text = textArea1.get("1.0", 'end-1c').splitlines()

        # function to deal with ascii format
        # It finds the source address of TC and
        # extracts DDOP data from TP and ETP protocols
        def look_in_ascii():
            tc_sa = ""
            dataBuffer1 = ""
            dataBuffer2 = ""
            dataBuffer = ""
            for line in text:
                if ('CBFF' in line and 'FE FF FF FF' in line) or (
                        'CBFF' in line and 'fe ff ff ff' in line):  # look for a line that has a status message that only TC can send
                    headerRegex = re.compile(r'CBFF\w\w')
                    found_header = headerRegex.search(line)
                    header = found_header.group()
                    tc_sa = header[4:]

                # Extract DDOP data from TP and ETP protocols
                if "EB" + tc_sa in line:
                    data = line[line.find('d'):line.find('L')].strip()
                    data = data[7:].replace(" ", "")
                    dataBuffer1 += data
                    start_of_ddop = dataBuffer1.find("614456")
                    dataBuffer1 = dataBuffer1[start_of_ddop:]

                if 'C7' + tc_sa in line:
                    data = line[line.find('d'):line.find('L')].strip()
                    data = data[7:].replace(" ", "")
                    dataBuffer2 += data
                    start_of_ddop = dataBuffer2.find("614456")
                    dataBuffer2 = dataBuffer2[start_of_ddop:]
            dataBuffer = dataBuffer1 + dataBuffer2
            print(tc_sa)
            print(dataBuffer)
            return dataBuffer

        # function to do the parsing on the data
        def data_parser(data_to_be_parsed):
            # Initialize XML document for writing to it
            global DVC
            root = minidom.Document()
            xml = root.createElement("ISO11783_TaskData")

            # function to convert hexadecimal to floating point number
            def hex_to_float(argument):
                argument = int(argument, 16)
                cp = pointer(c_int(argument))
                fp = cast(cp, POINTER(c_float))
                return '{0:.10f}'.format(fp.contents.value)

            # this function converts little endian hex to big endian hex
            def little_endian_to_big_endian(argument):
                argument = bytearray.fromhex(argument)
                argument.reverse()
                argument = int(''.join(format(n, '02x') for n in argument), 16)
                return argument

                # functions to parse Objects and write information to XML file

            def parse_write_DVC(count):
                XML_tag = ""  # This stands for string DVC
                ObjectID = ""  # This stands for DVC-#
                N_DVC = ""  # represents how many designator bytes will follow
                designator = ""  # holds device designator as a text
                M = ""  # represents how many software_version bytes will follow
                software_version = ""  # holds software_version bytes as text
                ClientName = ""  # holds client name bytes (8 bytes)
                o = ""  # represents how many serial number bytes will follow
                SerialNumber = ""  # holds device serial number bytes
                DeviceStructureLabel = ""  # holds device structure label ( it is 7 bytes long)
                DeviceLocalizationLabel = ""  # holds device localization label (it is 7 bytes long)

                for byte in data_to_be_parsed[index:index + 6]:
                    XML_tag += byte
                XML_tag = bytearray.fromhex(XML_tag).decode()
                dvc = root.createElement(XML_tag)

                # get Object ID
                for byte in data_to_be_parsed[index + 6:index + 10]:
                    ObjectID += byte
                dvc.setAttribute('A', 'DVC-' + str(count))

                #  get N
                for byte in data_to_be_parsed[index + 10:index + 12]:
                    N_DVC += byte
                N_DVC = int(N_DVC, 16)

                #  extract device designator bytes:
                for byte in data_to_be_parsed[index + 12:index + 12 + N_DVC * 2]:
                    designator += byte
                designator = bytearray.fromhex(designator).decode()
                dvc.setAttribute('B', designator)

                #  get M
                for byte in data_to_be_parsed[index + 12 + N_DVC * 2:index + 14 + N_DVC * 2]:
                    M += byte
                M = int(M, 16)

                #  extract device software version
                for byte in data_to_be_parsed[index + 14 + N_DVC * 2:index + 14 + N_DVC * 2 + M * 2]:
                    software_version += byte
                software_version = bytearray.fromhex(software_version).decode()
                dvc.setAttribute('C', software_version)

                # extract client device name
                for byte in data_to_be_parsed[index + 14 + N_DVC * 2 + M * 2:index + 14 + 16 + N_DVC * 2 + M * 2]:
                    ClientName += byte
                ClientName = bytearray.fromhex(ClientName)
                ClientName.reverse()
                ClientName = ''.join(format(n, '02x') for n in ClientName).upper()
                dvc.setAttribute('D', ClientName)

                #  Get O:
                for byte in data_to_be_parsed[index + 30 + N_DVC * 2 + M * 2:index + 32 + N_DVC * 2 + M * 2]:
                    o += byte
                o = int(o, 16)

                #  Extract Serial Number
                for byte in data_to_be_parsed[index + 32 + N_DVC * 2 + M * 2:index + 32 + N_DVC * 2 + M * 2 + o * 2]:
                    SerialNumber += byte
                SerialNumber = bytearray.fromhex(SerialNumber).decode()
                dvc.setAttribute('E', SerialNumber)

                #  Extract Device Structure Label
                for byte in data_to_be_parsed[
                            index + 32 + N_DVC * 2 + M * 2 + o * 2:index + 46 + N_DVC * 2 + M * 2 + o * 2]:
                    DeviceStructureLabel += byte
                DeviceStructureLabel = bytearray.fromhex(DeviceStructureLabel)
                DeviceStructureLabel.reverse()
                DeviceStructureLabel = ''.join(format(n, '02x') for n in DeviceStructureLabel).upper()
                dvc.setAttribute('F', DeviceStructureLabel)

                #  Extract Device Localization Label
                for byte in data_to_be_parsed[
                            index + 46 + N_DVC * 2 + M * 2 + o * 2:index + 60 + N_DVC * 2 + M * 2 + o * 2]:
                    DeviceLocalizationLabel += byte
                DeviceLocalizationLabel = bytearray.fromhex(DeviceLocalizationLabel)
                DeviceLocalizationLabel.reverse()
                DeviceLocalizationLabel = ''.join(format(n, '02x') for n in DeviceLocalizationLabel).upper()
                dvc.setAttribute('G', DeviceLocalizationLabel)

                xml.appendChild(dvc)
                return dvc

            def parse_write_DET(counter, dvc):
                XML_tag = ""
                ObjectID = ""
                Type = ""
                N_DET = ""
                designator = ""
                DeviceElementNumber = ""
                ParentObjectID = ""
                NumberOfObjectsToFollow = ""
                ID_string = ""
                # ID = ""

                for byte in data_to_be_parsed[index:index + 6]:
                    XML_tag += byte
                XML_tag = bytearray.fromhex(XML_tag).decode()
                DET = root.createElement(XML_tag)
                counter = str(counter)
                DET.setAttribute('A', 'DET-' + counter)

                # get Object_ID
                for byte in data_to_be_parsed[index + 6:index + 10]:
                    ObjectID += byte
                ObjectID = little_endian_to_big_endian(ObjectID)
                DET.setAttribute('B', str(ObjectID))

                # get DeviceElementType:
                for byte in data_to_be_parsed[index + 10:index + 12]:
                    Type += byte
                Type = str(int(Type, 16))
                DET.setAttribute('C', Type)

                #  get N
                for byte in data_to_be_parsed[index + 12:index + 14]:
                    N_DET += byte
                N_DET = int(N_DET, 16)

                #  extract device designator bytes:
                for byte in data_to_be_parsed[index + 14:index + 14 + N_DET * 2]:
                    designator += byte
                designator = bytearray.fromhex(designator).decode()
                DET.setAttribute('D', designator)

                # Extract Device Element Number:
                for byte in data_to_be_parsed[index + 14 + N_DET * 2:index + 18 + N_DET * 2]:
                    DeviceElementNumber += byte
                DeviceElementNumber = little_endian_to_big_endian(DeviceElementNumber)
                DET.setAttribute('E', str(DeviceElementNumber))

                # Extract ParentObjectID:
                for byte in data_to_be_parsed[index + 18 + N_DET * 2:index + 22 + N_DET * 2]:
                    ParentObjectID += byte
                ParentObjectID = little_endian_to_big_endian(ParentObjectID)
                DET.setAttribute('F', str(ParentObjectID))

                # Extract the number of objects to follow:
                for byte in data_to_be_parsed[index + 22 + N_DET * 2:index + 26 + N_DET * 2]:
                    NumberOfObjectsToFollow += byte
                NumberOfObjectsToFollow = little_endian_to_big_endian(NumberOfObjectsToFollow)

                # extract the ID's of following DOR objects:
                for byte in data_to_be_parsed[
                            index + 26 + N_DET * 2:index + 26 + N_DET * 2 + NumberOfObjectsToFollow * 4]:
                    ID_string += byte

                ID_list = [ID_string[i:i + 4] for i in range(0, len(ID_string), 4)]

                dvc.appendChild(DET)

                for number in range(len(ID_list)):
                    DOR = root.createElement("DOR")
                    ID = little_endian_to_big_endian(ID_list[number])
                    DOR.setAttribute('A', str(ID))
                    DET.appendChild(DOR)

            def parse_write_DPD(dvc):
                XML_tag = ""
                ObjectID = ""
                DDI = ""
                Property = ""
                TriggerMethods = ""
                N_DPD = ""
                designator = ""
                Presentation = ""

                for byte in data_to_be_parsed[index:index + 6]:
                    XML_tag += byte
                XML_tag = bytearray.fromhex(XML_tag).decode()
                DPD = root.createElement(XML_tag)

                for byte in data_to_be_parsed[index + 6:index + 10]:
                    ObjectID += byte
                ObjectID = little_endian_to_big_endian(ObjectID)
                DPD.setAttribute('A', str(ObjectID))

                for byte in data_to_be_parsed[index + 10:index + 14]:
                    DDI += byte
                DDI = bytearray.fromhex(DDI)
                DDI.reverse()
                DDI = ''.join(format(n, '02x') for n in DDI).upper()
                DPD.setAttribute('B', str(DDI))

                for byte in data_to_be_parsed[index + 14:index + 16]:
                    Property += byte
                Property = str(int(Property, 16))
                DPD.setAttribute('C', Property)

                for byte in data_to_be_parsed[index + 16:index + 18]:
                    TriggerMethods += byte
                TriggerMethods = str(int(TriggerMethods, 16))
                DPD.setAttribute('D', TriggerMethods)

                for byte in data_to_be_parsed[index + 18:index + 20]:
                    N_DPD += byte
                N_DPD = int(N_DPD, 16)

                for byte in data_to_be_parsed[index + 20:index + 20 + N_DPD * 2]:
                    designator += byte
                designator = bytearray.fromhex(designator).decode()
                DPD.setAttribute('E', designator)

                if data_buffer[index + 20 + N_DPD * 2:index + 24 + N_DPD * 2] != "FFFF":
                    for byte in data_to_be_parsed[index + 20 + N_DPD * 2:index + 24 + N_DPD * 2]:
                        Presentation += byte
                    Presentation = little_endian_to_big_endian(Presentation)
                    DPD.setAttribute('F', str(Presentation))
                dvc.appendChild(DPD)

            def parse_write_DPT(dvc):
                XML_tag = ""
                ObjectID = ""
                DDI = ""
                Value = ""
                N_DPT = ""
                designator = ""

                for byte in data_to_be_parsed[index:index + 6]:
                    XML_tag += byte
                XML_tag = bytearray.fromhex(XML_tag).decode()
                DPT = root.createElement(XML_tag)

                for byte in data_to_be_parsed[index + 6:index + 10]:
                    ObjectID += byte
                ObjectID = little_endian_to_big_endian(ObjectID)
                DPT.setAttribute('A', str(ObjectID))

                for byte in data_to_be_parsed[index + 10:index + 14]:
                    DDI += byte
                DDI = bytearray.fromhex(DDI)
                DDI.reverse()
                DDI = ''.join(format(n, '02x') for n in DDI).upper()
                DPT.setAttribute('B', str(DDI))

                for byte in data_to_be_parsed[index + 14:index + 18]:
                    Value += byte
                Value = little_endian_to_big_endian(Value)
                DPT.setAttribute('C', str(Value))

                for byte in data_to_be_parsed[index + 22:index + 24]:
                    N_DPT += byte
                N_DPT = int(N_DPT, 16)

                for byte in data_to_be_parsed[index + 24:index + 24 + N_DPT * 2]:
                    designator += byte
                designator = bytearray.fromhex(designator).decode()
                DPT.setAttribute('D', designator)

                dvc.appendChild(DPT)

            def parse_write_DVP(dvc):
                XML_tag = ""
                Object_ID = ""
                Offset = ""
                scale = ""
                NumerOfDecimals = ""
                N_DVP = ""
                designator = ""

                for byte in data_to_be_parsed[index:index + 6]:
                    XML_tag += byte
                XML_tag = bytearray.fromhex(XML_tag).decode()
                DVP = root.createElement(XML_tag)

                for byte in data_to_be_parsed[index + 6:index + 10]:
                    Object_ID += byte
                Object_ID = little_endian_to_big_endian(Object_ID)
                DVP.setAttribute('A', str(Object_ID))

                for byte in data_to_be_parsed[index + 10:index + 18]:
                    Offset += byte
                # Offset = little_endian_to_big_endian(Offset)
                Offset = bytearray.fromhex(Offset)
                Offset.reverse()
                Offset = ''.join(format(n, '02x') for n in Offset).upper()
                Offset = struct.unpack('>i', bytes.fromhex(Offset))[0]
                DVP.setAttribute('B', str(Offset))

                for byte in data_to_be_parsed[index + 18:index + 26]:
                    scale += byte
                scale = bytearray.fromhex(scale)
                scale.reverse()
                scale = ''.join(format(n, '02x') for n in scale).upper()
                DVP.setAttribute('C', hex_to_float(scale))

                for byte in data_to_be_parsed[index + 26:index + 28]:
                    NumerOfDecimals += byte
                NumerOfDecimals = int(NumerOfDecimals, 16)
                DVP.setAttribute('D', str(NumerOfDecimals))

                for byte in data_to_be_parsed[index + 28:index + 30]:
                    N_DVP += byte
                N_DVP = int(N_DVP, 16)

                for byte in data_to_be_parsed[index + 30:index + 30 + N_DVP * 2]:
                    designator += byte
                designator = bytearray.fromhex(designator).decode()
                DVP.setAttribute('E', designator)

                dvc.appendChild(DVP)

            #  loop through data buffer from beginning and parse data, write to XML file
            DET_count = 0
            DVC_count = 0
            index = 0
            for index, letter in enumerate(data_to_be_parsed):  # loop through buffer and assign indexes
                object_indicator = data_to_be_parsed[index:(index + 6)]  # 3-byte object indicator (## ## ##)
                match object_indicator:
                    case "445643":  # if "445643" is detected then this is the start of DeviceObject

                        DVC_count += 1
                        DVC = parse_write_DVC(DVC_count)

                    case "444554":  # if "444554" is detected,then this is the start of DeviceElementObject
                        DET_count += 1
                        parse_write_DET(DET_count, DVC)

                    case "445044":  # if "445044" is detected,then this is the start of DeviceProcessDataObject
                        parse_write_DPD(DVC)

                    case "445054":  # if "445054' is detected, then this is the start of DevicePropertyObject
                        parse_write_DPT(DVC)

                    case "445650":  # if "445660" is detected, then this is the start of DeviceValuePresentationObject
                        parse_write_DVP(DVC)

            # write and close output file
            root.appendChild(xml)
            xml_str = root.toprettyxml(indent="\t")
            textArea2.insert(END, xml_str)
            file = filedialog.asksaveasfile(defaultextension='.xml', filetypes=[("XML file", ".xml")])
            file.write(xml_str)
            file.close()

        # see what type of file it is and handle it accordingly
        match file_extension:
            case ".asc":
                data_buffer = look_in_ascii()
                data_parser(data_to_be_parsed=data_buffer)

            case ".blf":
                data_buffer = look_in_ascii()
                data_parser(data_to_be_parsed=data_buffer)

            case ".txt":
                for line in text:
                    if '61 44 56 43' in line:
                        start_point = line.find('61')
                        data_buffer = line[start_point:]
                data_buffer = data_buffer.replace(" ", "")
                data_parser(data_to_be_parsed=data_buffer)

    # set up the grid system
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=0)
    app.grid_columnconfigure(2, weight=1)
    app.grid_rowconfigure(0, weight=1)

    # Create 3 frames (left, middle, and right)
    left_frame = customtkinter.CTkFrame(master=app,  corner_radius=20, width=400,)
    left_frame.grid(row=0, column=0, sticky='nsew', pady=10, padx=10)
    middle_frame = customtkinter.CTkFrame(master=app)
    middle_frame.grid(row=0, column=1)
    right_frame = customtkinter.CTkFrame(master=app, corner_radius=20, width=400)
    right_frame.grid(row=0, column=2, sticky='nsew', padx=10, pady=10)

    # set up the grid for the left frame
    left_frame.grid_rowconfigure(2, weight=1)
    left_frame.grid_columnconfigure(0, weight=1)
    left_frame.grid_columnconfigure(1, weight=0)

    # Create label1 and textArea1 in left_frame
    label1 = customtkinter.CTkLabel(master=left_frame, text='CAN trace', text_font=('Arial', 16))
    textArea1 = tkinter.Text(master=left_frame)
    label1.grid(row=0, column=0, padx=20, pady=20, sticky='nsew')
    textArea1.grid(row=2, column=0, sticky='nsew',)

    # create scrollbar for left frame
    scrollbar1 = customtkinter.CTkScrollbar(left_frame, command=textArea1.yview)
    scrollbar1.grid(row=2, column=1, sticky='nsew')
    textArea1.configure(yscrollcommand=scrollbar1.set)

    # set up the grid for the right frame
    right_frame.grid_rowconfigure(2, weight=1)
    right_frame.grid_columnconfigure(0, weight=1)
    right_frame.grid_columnconfigure(1, weight=0)

    # Create label1 and textArea1 in right frame
    label2 = customtkinter.CTkLabel(master=right_frame, text='XML output file', text_font=('Arial', 16))
    textArea2 = tkinter.Text(master=right_frame)
    label2.grid(row=0, column=0, padx=20, pady=20, sticky='nsew')
    textArea2.grid(row=2, column=0, sticky='nsew')

    # Create scrollbar for right frame
    scrollbar3 = customtkinter.CTkScrollbar(right_frame, command=textArea2.yview)
    scrollbar3.grid(row=2, column=1, sticky="nsew")
    textArea2.configure(yscrollcommand=scrollbar3.set)

    # set up the grid for middle frame
    middle_frame.grid_rowconfigure(0, weight=0)
    middle_frame.grid_rowconfigure(1, weight=1)
    middle_frame.grid_columnconfigure(0, weight=1)

    # create buttons in middle_frame
    button1 = customtkinter.CTkButton(master=middle_frame, text='Open file', border_width=2, command=open_file,
                                      border_color="white", text_font=("Arial", 12))
    button2 = customtkinter.CTkButton(master=middle_frame, text='Convert', command=convert_file, border_width=2,
                                      border_color="white", text_font=("Arial", 12))
    button1.grid(row=0, column=0, pady=10, padx=10)
    button2.grid(row=1, column=0, pady=10, padx=10)

    app.mainloop()


if __name__ == '__main__':
    main()
