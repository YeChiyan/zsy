package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Event;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.dao.ExcelEventDao;
import com.cug.cs.overseaprojectinformationsystem.service.EventService;
import com.cug.cs.overseaprojectinformationsystem.util.CenterNameutil;
import com.cug.cs.overseaprojectinformationsystem.util.EventWayUtil;
import com.cug.cs.overseaprojectinformationsystem.util.ExcelUtil;
import com.cug.cs.overseaprojectinformationsystem.util.PathUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.print.Book;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
/**
 * @author shentong
 * @date 2023/9/18 18:10
 * @description 市场营销Controller
 */
@RestController
@Slf4j
@RequestMapping("/market")
public class EventController {
    @Autowired
    private EventService eventService;

    /*@GetMapping("/events")
    public Result getEventList(HttpServletRequest request) {
        List<Event> eventList = eventService.getAll();
        Integer code = eventList != null ? Code.GET_OK : Code.GET_ERR;
        String msg = eventList != null ? "数据查询成功！" : "数据查询失败，请重试！";
        return new Result(code,eventList,msg);
    }*/
    /*@RequiresPermissions("market:events:list")*/
    @GetMapping("/events")
    public ResData getEventList(PageBaseInfo pageBaseInfo){
        PageBean pageBean = eventService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean,"success");
    }

    /*@PostMapping("/events")
    public Result addEvent(@RequestBody Event event) {
        boolean flag = eventService.add(event);
        return new Result(flag ? Code.ADD_OK:Code.ADD_ERR,flag);
    }*/
    //@RequiresPermissions("market:events:add")
    @PostMapping("/events")
    public ResponseData addEvent(@RequestBody Event event) {
        eventService.add(event);
        return new ResponseUtil<Event>().setData(event,"success");
    }

    //@RequiresPermissions("market:events:update")
    @PutMapping("/events")
    public ResponseData updateEvent(@RequestBody Event event) {
        eventService.update(event);
        return new ResponseUtil<>().setData(null,"message");
    }

    //@RequiresPermissions("market:events:delete")
    @DeleteMapping("/events")
    public ResponseData deleteEvent(Integer id) {
        eventService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }

//    文件输出
    @Autowired
    ExcelEventDao excelEventDao;
    @ResponseBody
    @GetMapping("/eventexcel")
    public void eventExport(HttpServletResponse response) throws IOException {
        String fileName = "市场营销.xlsx";
        String[] sheetName = {"市场营销"};
        String[] title = {"序号","客户名称","时间","组织单位","沟通内容","方式","地点","主要负责人","参与人员","备注"};
        List<Event> eventList = excelEventDao.selectList(null);
        String[][] content = new String[eventList.size()][title.length];
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出合同管理表格
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出市场营销
        for (int i = 0;i<eventList.size();i++){
            String[] row = content[i];
            Event event = eventList.get(i);
            row[0] = String.valueOf(event.getId());
            row[1] = event.getClientName();
            row[2] = String.valueOf(event.getDate());
            row[3] = event.getOrgUnit();
            row[4] = event.getContent();
            row[5] = EventWayUtil.swithWay(event.getWay());
            row[6] = event.getLocation();
            row[7] = event.getHead();
            row[8] = event.getParticipants();
            row[9] = event.getNote();
        }
        log.info("————————————————————市场营销导出完成————————————————————");

        XSSFWorkbook workbook = ExcelUtil.getWorkbook(sheetName, title, content,false);
        log.info("-————————————————————数据已写入文件————————————————————-");

        // TODO 这里路径写死了，前端可以传一个路径进来，不同的用户路径是不同的
        String path = PathUtil.getPath()+fileName;
        log.info(path);

        FileOutputStream out = new FileOutputStream(new File(path));
        workbook.write(out);
        log.info("——————————————————————文件已输出——————————————————————");

        try{
            URL url = new File(path).toURI().toURL();
            URLConnection conn = url.openConnection();
            InputStream inputStream = conn.getInputStream();
            response.reset();
            response.setContentType(conn.getContentType());
            String filename = "市场营销.xlsx";
            response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(filename, "UTF-8"));
            byte[] buffer = new byte[1024];
            int len;
            OutputStream outputStream = response.getOutputStream();
            while ((len = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }
            inputStream.close();
        }
        catch (IOException e){
            throw new IOException(e);
        }
    }
}
