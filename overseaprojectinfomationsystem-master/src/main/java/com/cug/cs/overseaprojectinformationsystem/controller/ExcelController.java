//package com.cug.cs.overseaprojectinformationsystem.cotroller;
//
//import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
//import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
//import com.cug.cs.overseaprojectinformationsystem.dal.entitys.*;
//import com.cug.cs.overseaprojectinformationsystem.dao.*;
//import com.cug.cs.overseaprojectinformationsystem.util.ExcelUtil;
//import com.cug.cs.overseaprojectinformationsystem.util.EventWayUtil;
//import com.cug.cs.overseaprojectinformationsystem.util.BidWayUtil;
//import com.cug.cs.overseaprojectinformationsystem.util.NewSignUtil;
//import lombok.extern.slf4j.Slf4j;
//import org.apache.poi.xssf.usermodel.XSSFWorkbook;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.ResponseBody;
//import org.springframework.web.bind.annotation.RestController;
//
//import javax.servlet.http.HttpServletResponse;
//import java.io.*;
//import java.net.URL;
//import java.net.URLConnection;
//import java.net.URLEncoder;
//import java.util.List;
//
///**
// * @ClassName ExcelController
// * @Description TODO 表的导出
// * @Author Zhangz
// * @Date 2023/9/20 15:31
// * @Version 1.0
// **/
//@RestController
//@RequestMapping("/market")
//@Slf4j
//public class ExcelController {
//    @Autowired
//    ExcelPotDao excelPotDao;
//    @Autowired
//    ExcelBidDao excelBidDao;
//    @Autowired
//    ExcelNewDao excelNewDao;
//    @Autowired
//    ExcelEventDao excelEventDao;
//    @Autowired
//    ExcelPreDao excelPreDao;
//
//    @ResponseBody
//    @RequestMapping("/exportexceltotal")
//    public void exportExcel(HttpServletResponse response) throws IOException {
//        String fileName = "导出市场文件.xlsx";
//        String[] sheetName = {"市场营销","技术宣讲","潜在项目","投标统计","新签市场"};
//        String[][] title = {
//                {"序号","客户名称","时间","组织单位","沟通内容","方式","地点","主要负责人","参与人员","备注"},
//                {"序号","主办单位","宣讲主题","营销内容","宣讲形式","地点","涉及油公司","日期","报告&筹备人员","备注"},
//                {"海外中心","项目名称","国家","客户","工作量","合同额（万美元）","类型","落实程度","重要动态"},
//                {"序号","地区","国家","甲方","项目名称","邀标时间","闭标时间","业务类别","投标主体","是否总部支持",
//                        "招标方式","评标动态","中/落/弃标时间","落/弃标原因","预计合同额（万美元）","工作量","单价",
//                        "总价","是否一体化","备注（请标注汇率）"},
//                {"地区","国家","工区名称","甲方","我方签约公司名称","我方合同签字人姓名","项目名称","合同号","工作性质","是否一体化项目",
//                        "工区地表类型","是否PSTM","是否PSDM","工作量","新签合同额（万美元）","合同签订日期","合同关闭日期","备注"}
//        };
//        List<Event> eventList = excelEventDao.selectList(null);
//        List<Presentation> presentationList = excelPreDao.selectList(null);
//        List<PotProject> potPorjectlist = excelPotDao.selectList(null);
//        List<Bid> bidList = excelBidDao.selectList(null);
//        List<NewSign> newSignList = excelNewDao.selectList(null);
//        String[][] content0 = new String[eventList.size()][title[0].length];
//        String[][] content1 = new String[presentationList.size()][title[1].length];
//        String[][] content2 = new String[potPorjectlist.size()][title[2].length];
//        String[][] content3 = new String[bidList.size()][title[3].length];
//        String[][] content4 = new String[newSignList.size()][title[4].length];
//
//        log.info("——————————————————————准备工作完成——————————————————————");
//        //导出市场营销
//        for (int i = 0;i<eventList.size();i++){
//            String[] row = content0[i];
//            Event event = eventList.get(i);
//            row[0] = String.valueOf(event.getId());
//            row[1] = event.getClientName();
//            row[2] = String.valueOf(event.getDate());
//            row[3] = event.getOrgUnit();
//            row[4] = event.getContent();
//            row[5] = EventWayUtil.swithWay(event.getWay());
//            row[6] = event.getLocation();
//            row[7] = event.getHead();
//            row[8] = event.getParticipants();
//            row[9] = event.getNote();
//        }
//        log.info("————————————————————市场营销导出完成————————————————————");
//        //导出科技宣讲
//        for (int i = 0;i<presentationList.size();i++){
//            String[] row = content1[i];
//            Presentation presentation = presentationList.get(i);
//            row[0] = String.valueOf(presentation.getId());
//            row[1] = presentation.getOrganizer();
//            row[2] = presentation.getPreTheme();
//            row[3] = presentation.getPreContent();
//            row[4] = presentation.getPreFormat();
//            row[5] = presentation.getPrePlace();
//            row[6] = presentation.getComInvolved();
//            row[7] = presentation.getStartTime() +"——"+ presentation.getEndTime();
//            row[8] = presentation.getStaff();
//            row[9] = presentation.getNote();
//        }
//        log.info("————————————————————科技宣讲导出完成————————————————————");
//        //导出潜在项目
//        for (int i = 0;i<potPorjectlist.size();i++){
//            String[] row = content2[i];
//            PotProject potProject = potPorjectlist.get(i);
//            row[0] = potProject.getCenterName();
//            row[1] = potProject.getProjectName();
//            row[2] = potProject.getCountry();
//            row[3] = potProject.getClientName();
//            row[4] = potProject.getWorkloadKm()+"km"+ potProject.getWorkloadSqkm()+"sqkm";
//            row[5] = String.valueOf(potProject.getContract());
//            row[6] = potProject.getConType();
//            row[7] = potProject.getFulfilExtent();
//            row[8] = potProject.getImpActive();
//        }
//        log.info("————————————————————潜在项目导出完成————————————————————");
//        //导出投标项目
//        for(int i = 0;i<bidList.size();i++){
//            String[] row = content3[i];
//            Bid bid = bidList.get(i);
//            row[0] = String.valueOf(bid.getId());
//            row[1] = bid.getArea();
//            row[2] = bid.getCountry();
//            row[3] = bid.getLessor();
//            row[4] = bid.getProjectName();
//            row[5] = String.valueOf(bid.getInviteTime());
//            row[6] = String.valueOf(bid.getCloseTime());
//            row[7] = BidWayUtil.toType(bid.getBusidateType());
//            row[8] = bid.getTenderBody();
//            row[9] = BidWayUtil.toSupport(bid.getSupport());
//            row[10] = BidWayUtil.toMethod(bid.getTenderMethod());
//            row[11] = BidWayUtil.toDynamics(bid.getEvaDynamics());
//            row[12] = String.valueOf(bid.getDate());
//            row[13] = bid.getReason();
//            row[14] = String.valueOf(bid.getAmount());
//            row[15] = String.valueOf(bid.getWorkload());
//            row[16] = String.valueOf(bid.getUnivalent());
//            row[17] = String.valueOf(bid.getPrive());
//            row[18] = BidWayUtil.toInt(bid.getIntegration());
//            row[19] = bid.getNote();
//        }
//        log.info("————————————————————投标项目导出完成————————————————————");
//        //导出新签市场
//        for(int i = 0;i<newSignList.size();i++) {
//            String[] row = content4[i];
//            NewSign newSign = newSignList.get(i);
//            row[0] = newSign.getArea();
//            row[1] = newSign.getCountry();
//            row[2] = newSign.getWorkareaName();
//            row[3] = newSign.getLessor();
//            row[4] = newSign.getOurCompany();
//            row[5] = newSign.getSignatoryName();
//            row[6] = newSign.getProjectName();
//            row[7] = newSign.getContractNum();
//            row[8] = newSign.getWorkNature();
//            row[9] = NewSignUtil.toInt(newSign.getIntegration());
//            row[10] = newSign.getSurfaceType();
//            row[11] = NewSignUtil.toPstm(newSign.getPstm());
//            row[12] = newSign.getPsdm();
//            row[13] = newSign.getWorkload_2d()+"km"+newSign.getWorkload_3d()+"sqkm";
//            row[14] = String.valueOf(newSign.getContractAmount());
//            row[15] = String.valueOf(newSign.getSignDate());
//            row[16] = String.valueOf(newSign.getCloseDate());
//            row[17] = newSign.getNote();
//        }
//        log.info("————————————————————新签市场导出完成————————————————————");
//
//        XSSFWorkbook workbook = ExcelUtil.getWorkbook(sheetName, title, content0,content1,content2,content3,content4);
//        log.info("-————————————————————数据已写入文件————————————————————-");
//        // TODO 这里路径写死了，前端可以传一个路径进来，不同的用户路径是不同的
//        String path = "D:\\a_java\\ospf\\src\\main\\resources\\"+fileName;
//        log.info(path);
//
//        FileOutputStream out = new FileOutputStream(new File(path));
//        workbook.write(out);
//        log.info("——————————————————————文件已输出——————————————————————");
//
//        log.info("测试文件下载");
//
//        URL url = new File(path).toURI().toURL();
//        URLConnection conn = url.openConnection();
//        InputStream inputStream = conn.getInputStream();
//        log.info("111");
//        response.reset();
//        response.setContentType(conn.getContentType());
//        String filename = "市场部文件下载.xlsx";
//        response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(filename, "UTF-8"));
//        log.info("222");
//        byte[] buffer = new byte[1024];
//        int len;
//        OutputStream outputStream = response.getOutputStream();
//        while ((len = inputStream.read(buffer)) > 0) {
//            outputStream.write(buffer, 0, len);
//        }
//        inputStream.close();
//        // return  new ResponseUtil<>().setData("success");
//
////        outputStream = null;
////        try {
////            outputStream = response.getOutputStream();
////            response.reset();
////            //设置响应头
////            fileName = new String(fileName.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
////            response.setContentType("application/msexcel");// 定义输出类型
////            response.setCharacterEncoding("utf-8");
////            response.setHeader("Content-disposition", "attachment; filename=" + URLEncoder.encode(fileName, "UTF-8"));
////            response.addHeader("Pargam", "no-cache");
////            response.addHeader("Cache-Control", "no-cache");
////
////            //获取输出流
////            outputStream = response.getOutputStream();
////            //用文档写输出流
////            workbook.write(outputStream);
////
////            //刷新输出流
////            outputStream.flush();
////        } catch (Exception e) {
////            e.printStackTrace();
////        } finally {
////            //关闭输出流
////            if (outputStream != null) {
////                try {
////                    outputStream.close();
////                } catch (IOException e) {
////                    e.printStackTrace();
////                }
////            }
////        }
//    }
//}
//
//
//
//
