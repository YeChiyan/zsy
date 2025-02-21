package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.Presentation;
import com.cug.cs.overseaprojectinformationsystem.dao.ExcelPreDao;
import com.cug.cs.overseaprojectinformationsystem.service.PresentationService;
import com.cug.cs.overseaprojectinformationsystem.util.ExcelUtil;
import com.cug.cs.overseaprojectinformationsystem.util.PathUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.List;
/**
 * @author shentong
 * @date 2023/9/18 18:10
 * @description 技术宣讲Controller
 */
@RestController
@Slf4j
@RequestMapping("/market")
public class PresentationController {
    @Autowired
    private PresentationService presentationService;

    @RequiresPermissions("market:presentations:list")
    @GetMapping("/presentations")
    public ResData getPresentationsList(PageBaseInfo pageBaseInfo){
        PageBean pageBean = presentationService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean,"success");
    }

    @RequiresPermissions("market:presentations:add")
    @PostMapping("/presentations")
    public ResponseData addPresentation(@RequestBody Presentation presentation) {
        presentationService.add(presentation);
        return new ResponseUtil<Presentation>().setData(presentation,"success");
    }

    @RequiresPermissions("market:presentations:update")
    @PutMapping("/presentations")
    public ResponseData updatePresentation(@RequestBody Presentation presentation) {
        presentationService.update(presentation);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("market:presentations:delete")
    @DeleteMapping("/presentations")
    public ResponseData deletePresentation(Integer id) {
        presentationService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }


//    文件导出
    @Autowired
    ExcelPreDao excelPreDao;
    @ResponseBody
    @RequestMapping("/preexcel")
    public void preExport(HttpServletResponse response) throws IOException {
        String fileName = "技术宣讲.xlsx";
        String[] sheetName = {"技术宣讲"};
        String[] title = {"序号","主办单位","宣讲主题","营销内容","宣讲形式","地点","涉及油公司","日期","报告&筹备人员","备注"};
        List<Presentation> presentationList = excelPreDao.selectList(null);
        String[][] content = new String[presentationList.size()][title.length];
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出合同管理表格
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出市场营销
        for (int i = 0;i<presentationList.size();i++){
            String[] row = content[i];
            Presentation presentation = presentationList.get(i);
            row[0] = String.valueOf(presentation.getId());
            row[1] = presentation.getOrganizer();
            row[2] = presentation.getPreTheme();
            row[3] = presentation.getPreContent();
            row[4] = presentation.getPreFormat();
            row[5] = presentation.getPrePlace();
            row[6] = presentation.getComInvolved();
            row[7] = presentation.getStartTime() +"——"+ presentation.getEndTime();
            row[8] = presentation.getStaff();
            row[9] = presentation.getNote();
        }
        log.info("————————————————————技术宣讲出完成————————————————————");

        XSSFWorkbook workbook = ExcelUtil.getWorkbook(sheetName, title, content,true);
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
            String filename = "技术宣讲.xlsx";
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
