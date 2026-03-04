# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import ReportStatus
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import (
    VisualizableColor,
    VisualizableIcon,
    VisualizableSize,
)

logger = getLogger(__name__)


class SampleStaticAnalysis(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    # --- Page 1: Overview & Hash Lookups ---

    @visualizable_error_handler_with_params("File Info", "MD5", "SHA256")
    def _file_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="File_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("File_Info report does not exist")
            return self.Title(
                self.Base(value="File Info", icon=VisualizableIcon.INFO),
                self.Base(value="not available"),
                disable=True,
            )
        else:
            report = analyzer_report.report
            md5 = report.get("md5", "")
            sha256 = report.get("sha256", "")
            file_type = report.get("type", "")
            mimetype = report.get("mimetype", "")
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            file_info_title = self.Title(
                self.Base(value="File Info", icon=VisualizableIcon.INFO),
                self.Base(value=file_type or mimetype or ""),
                disable=disabled,
            )
            md5_elem = self.Title(
                self.Base(value="MD5", color=VisualizableColor.DARK),
                self.Base(value=md5, copy_text=md5),
                disable=disabled or not md5,
            )
            sha256_elem = self.Title(
                self.Base(value="SHA256", color=VisualizableColor.DARK),
                self.Base(value=sha256[:16] + "..." if sha256 else "", copy_text=sha256),
                disable=disabled or not sha256,
            )
            return file_info_title, md5_elem, sha256_elem

    @visualizable_error_handler_with_params("Cymru Hash")
    def _cymru_hash(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Cymru_Hash_Registry_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Cymru_Hash_Registry_Get_File report does not exist")
        else:
            detected = analyzer_report.report.get("detected", False)
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            return self.Bool(
                value="Cymru Hash",
                disable=not (not disabled and detected),
            )

    @visualizable_error_handler_with_params("HybridAnalysis")
    def _hybrid_analysis(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="HybridAnalysis_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("HybridAnalysis_Get_File report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {} and report != []
            return self.Title(
                self.Base(
                    value="HybridAnalysis",
                    icon=VisualizableIcon.HYBRIDAnalysis,
                ),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("MalwareBazaar")
    def _malware_bazaar(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="MalwareBazaar_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("MalwareBazaar_Get_File report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            query_status = report.get("query_status", "")
            found = query_status == "ok"
            return self.Title(
                self.Base(value="MalwareBazaar", icon=VisualizableIcon.MALWARE),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("OTX Check Hash")
    def _otx_check_hash(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="OTX_Check_Hash")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OTX_Check_Hash report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            pulses = report.get("pulse_info", {}).get("pulses", [])
            found = len(pulses) > 0
            otx_report = self.Title(
                self.Base(
                    value="OTX Check Hash",
                    icon=VisualizableIcon.OTX,
                ),
                self.Base(
                    value=f"{len(pulses)} pulse(s)" if found else "not found",
                ),
                disable=disabled or not found,
            )
            return otx_report

    @visualizable_error_handler_with_params("HashLookup")
    def _hashlookup(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="HashLookupServer_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("HashLookupServer_Get_File report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {} and "Not Found" not in str(report)
            return self.Title(
                self.Base(value="HashLookup"),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("YARAify")
    def _yaraify(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="YARAify_File_Search")
        except AnalyzerReport.DoesNotExist:
            logger.warning("YARAify_File_Search report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            query_status = report.get("query_status", "")
            found = query_status == "ok"
            return self.Title(
                self.Base(value="YARAify"),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    # --- Page 2: Binary & Document Analysis ---

    @visualizable_error_handler_with_params("PE Info", "Sections")
    def _pe_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="PE_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("PE_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            machine = report.get("machine_type", "")
            sections = report.get("sections", [])
            section_names = [s.get("name", "") for s in sections if s.get("name")]
            pe_title = self.Title(
                self.Base(value="PE Info", icon=VisualizableIcon.INFO),
                self.Base(value=machine or "PE"),
                disable=disabled,
            )
            pe_sections = self.VList(
                name=self.Base(
                    value="Sections",
                    disable=disabled or not section_names,
                ),
                value=[self.Base(value=name, disable=disabled) for name in section_names],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not section_names,
            )
            return pe_title, pe_sections

    @visualizable_error_handler_with_params("ELF Info")
    def _elf_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="ELF_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("ELF_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            arch = report.get("arch", "")
            elf_type = report.get("type", "")
            return self.Title(
                self.Base(value="ELF Info", icon=VisualizableIcon.INFO),
                self.Base(value=f"{elf_type} ({arch})" if arch else elf_type or "ELF"),
                disable=disabled,
            )

    @visualizable_error_handler_with_params("APKiD")
    def _apkid(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="APKiD")
        except AnalyzerReport.DoesNotExist:
            logger.warning("APKiD report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            detections = []
            if isinstance(report, dict):
                for _, rules in report.items():
                    if isinstance(rules, dict):
                        for rule_type, matches in rules.items():
                            if isinstance(matches, list):
                                for m in matches:
                                    detections.append(f"{rule_type}: {m}")
            return self.VList(
                name=self.Base(
                    value="APKiD",
                    disable=disabled or not found,
                ),
                value=[self.Base(value=d, disable=disabled) for d in detections[:10]],
                start_open=False,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("GoReSym")
    def _goresym(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="GoReSym")
        except AnalyzerReport.DoesNotExist:
            logger.warning("GoReSym report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            build_info = ""
            if isinstance(report, dict):
                build_info = report.get("BuildInfo", {})
                if isinstance(build_info, dict):
                    build_info = build_info.get("GoVersion", "")
            return self.Title(
                self.Base(value="GoReSym"),
                self.Base(value=build_info if build_info else "analyzed"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("Doc Info")
    def _doc_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Doc_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Doc_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            macros = []
            if isinstance(report, dict):
                macros = report.get("macros", [])
            has_macros = bool(macros)
            return self.Title(
                self.Base(
                    value="Doc Info",
                    icon=(VisualizableIcon.WARNING if has_macros else VisualizableIcon.INFO),
                    color=(VisualizableColor.DANGER if has_macros else VisualizableColor.INFO),
                ),
                self.Base(value="macros detected" if has_macros else "clean"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("PDF Info")
    def _pdf_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="PDF_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("PDF_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            # Check for suspicious elements
            suspicious = False
            if isinstance(report, dict):
                for key in ["js", "javascript", "openaction", "launch"]:
                    if report.get(key, 0):
                        suspicious = True
                        break
            return self.Title(
                self.Base(
                    value="PDF Info",
                    icon=(VisualizableIcon.WARNING if suspicious else VisualizableIcon.INFO),
                    color=(VisualizableColor.DANGER if suspicious else VisualizableColor.INFO),
                ),
                self.Base(value="suspicious" if suspicious else "clean"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("OneNote Info")
    def _onenote_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="OneNote_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OneNote_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(value="OneNote Info"),
                self.Base(value="analyzed" if found else ""),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("RTF Info")
    def _rtf_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Rtf_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Rtf_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(value="RTF Info"),
                self.Base(value="analyzed" if found else ""),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("XLM Macro")
    def _xlm_macro(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Xlm_Macro_Deobfuscator")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Xlm_Macro_Deobfuscator report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(
                    value="XLM Macro",
                    icon=VisualizableIcon.WARNING if found else VisualizableIcon.EMPTY,
                    color=VisualizableColor.DANGER if found else VisualizableColor.INFO,
                ),
                self.Base(value="macros found" if found else ""),
                disable=disabled or not found,
            )

    # --- Page 3: Signatures & Strings ---

    @visualizable_error_handler_with_params("Yara", "Yara Signatures")
    def _yara(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Yara")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Yara report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            num_matches = sum(len(matches) for matches in report.values())
            signatures = [
                match.get("match", "")
                for matches in report.values()
                for match in matches
                if match.get("match")
            ]
            yara_title = self.Title(
                self.Base(
                    value="Yara",
                    icon=VisualizableIcon.SHIELD,
                    color=(VisualizableColor.DANGER if num_matches else VisualizableColor.INFO),
                ),
                self.Base(value=f"{num_matches} match(es)"),
                disable=disabled or not num_matches,
            )
            yara_sigs = self.VList(
                name=self.Base(
                    value="Yara Signatures",
                    disable=disabled or not signatures,
                ),
                value=[self.Base(value=sig, disable=disabled) for sig in signatures],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not signatures,
            )
            return yara_title, yara_sigs

    @visualizable_error_handler_with_params("Signature Info")
    def _signature_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Signature_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Signature_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(
                    value="Signature Info",
                    icon=VisualizableIcon.SHIELD,
                ),
                self.Base(value="signed" if found else "not signed"),
                disable=disabled,
            )

    @visualizable_error_handler_with_params("ClamAV")
    def _clamav(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="ClamAV")
        except AnalyzerReport.DoesNotExist:
            logger.warning("ClamAV report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            malicious = False
            detection = ""
            if isinstance(report, dict):
                malicious = report.get("is_infected", False)
                detections = report.get("detections", [])
                if detections:
                    detection = detections[0] if isinstance(detections[0], str) else str(detections[0])
            return self.Title(
                self.Base(
                    value="ClamAV",
                    icon=(VisualizableIcon.MALWARE if malicious else VisualizableIcon.SHIELD),
                    color=(VisualizableColor.DANGER if malicious else VisualizableColor.SUCCESS),
                ),
                self.Base(value=detection if malicious else "clean"),
                disable=disabled,
            )

    @visualizable_error_handler_with_params("Quark Engine")
    def _quark_engine(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Quark_Engine")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Quark_Engine report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            threat_level = ""
            if isinstance(report, dict):
                threat_level = report.get("threat_level", "")
            return self.Title(
                self.Base(value="Quark Engine"),
                self.Base(value=threat_level if threat_level else "analyzed"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("Strings Info")
    def _strings_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Strings_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Strings_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report)
            num_strings = 0
            if isinstance(report, list):
                num_strings = len(report)
            elif isinstance(report, dict):
                num_strings = len(report.get("strings", []))
            return self.Title(
                self.Base(value="Strings Info"),
                self.Base(value=f"{num_strings} string(s)" if num_strings else "analyzed"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("Floss")
    def _floss(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Floss")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Floss report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            decoded_strings = []
            if isinstance(report, dict):
                decoded_strings = report.get("decoded_strings", [])
                if not decoded_strings:
                    decoded_strings = report.get("stack_strings", [])
            return self.VList(
                name=self.Base(
                    value="Floss Strings",
                    disable=disabled or not decoded_strings,
                ),
                value=[
                    self.Base(value=s if isinstance(s, str) else str(s), disable=disabled)
                    for s in decoded_strings[:20]
                ],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("Capa Info")
    def _capa_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Capa_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Capa_Info report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            capabilities = []
            if isinstance(report, dict):
                rules = report.get("rules", {})
                if isinstance(rules, dict):
                    capabilities = list(rules.keys())
            return self.VList(
                name=self.Base(
                    value="Capa Capabilities",
                    icon=VisualizableIcon.MAGNIFYING_GLASS,
                    disable=disabled or not capabilities,
                ),
                value=[self.Base(value=cap, disable=disabled) for cap in capabilities[:20]],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not capabilities,
                size=VisualizableSize.S_4,
            )

    @visualizable_error_handler_with_params("BoxJS")
    def _boxjs(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="BoxJS")
        except AnalyzerReport.DoesNotExist:
            logger.warning("BoxJS report does not exist")
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            urls = []
            if isinstance(report, dict):
                urls = report.get("urls", [])
            return self.VList(
                name=self.Base(
                    value="BoxJS URLs",
                    icon=VisualizableIcon.WARNING if urls else VisualizableIcon.EMPTY,
                    color=VisualizableColor.DANGER if urls else VisualizableColor.INFO,
                    disable=disabled or not found,
                ),
                value=[self.Base(value=url, disable=disabled) for url in urls[:10]],
                start_open=False,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled or not found,
            )

    # --- run ---

    def run(self) -> List[Dict]:
        # --- Page 1: Overview & Hash Lookups ---
        page1 = self.Page(name="Overview")

        file_info_result = self._file_info()
        if isinstance(file_info_result, (tuple, list)):
            overview_elements = list(file_info_result)
        else:
            overview_elements = [file_info_result]

        page1.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=overview_elements),
            )
        )

        hash_lookup_elements = [
            self._cymru_hash(),
            self._hybrid_analysis(),
            self._malware_bazaar(),
            self._otx_check_hash(),
            self._hashlookup(),
            self._yaraify(),
        ]
        page1.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=hash_lookup_elements),
            )
        )

        # --- Page 2: Binary & Document Analysis ---
        page2 = self.Page(name="Binary & Document Analysis")

        binary_elements = []
        pe_result = self._pe_info()
        if isinstance(pe_result, (tuple, list)):
            binary_elements.extend(pe_result)
        elif pe_result:
            binary_elements.append(pe_result)

        binary_elements.append(self._elf_info())
        binary_elements.append(self._apkid())
        binary_elements.append(self._goresym())

        page2.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=binary_elements),
            )
        )

        doc_elements = [
            self._doc_info(),
            self._pdf_info(),
            self._onenote_info(),
            self._rtf_info(),
            self._xlm_macro(),
        ]
        page2.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=doc_elements),
            )
        )

        # --- Page 3: Signatures & Strings ---
        page3 = self.Page(name="Signatures & Strings")

        sig_elements = []
        yara_result = self._yara()
        if isinstance(yara_result, (tuple, list)):
            sig_elements.extend(yara_result)
        elif yara_result:
            sig_elements.append(yara_result)

        sig_elements.append(self._signature_info())
        sig_elements.append(self._clamav())
        sig_elements.append(self._quark_engine())

        page3.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=sig_elements),
            )
        )

        string_elements = [
            self._strings_info(),
            self._floss(),
            self._capa_info(),
            self._boxjs(),
        ]
        page3.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=string_elements),
            )
        )

        logger.debug(f"page1: {page1.to_dict()}")
        logger.debug(f"page2: {page2.to_dict()}")
        logger.debug(f"page3: {page3.to_dict()}")
        return [page1.to_dict(), page2.to_dict(), page3.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
