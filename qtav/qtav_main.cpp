#include <limits>
#include <QtCore/qmath.h>
#include <QtCore/QCoreApplication>
#include <QtCore/QElapsedTimer>
#include <QtCore/QStringList>
#include <QtAV/AudioOutput.h>
#include <QtAV/AudioOutputTypes.h>
#include <QtDebug>

using namespace QtAV;
const int kTableSize = 200;
const int kFrames = 1024;
qint16 sin_table[kTableSize];

void help()
{
	QStringList backends;
	std::vector<std::string> names = AudioOutputFactory::registerdNames();
	for(int i = 0; i < (int)names.size(); i++) {
		backends.append(names[i].c_str());
	}
	qDebug() << "parameters: [-ao " << backends.join("|") << "]";
}

int main(int argc, char **argv)
{
	help();
	
	/** initialize sinusoidal wavetable **/
	for(int i = 0; i < kTableSize; i++){
		sin_table[i] = (qint16)((double)std::numeric_limits<qint16>::max() * sin(((double)i / (double)kTableSize) * 3.1415926 * 2.0));
	}
	QCoreApplication app(argc, argv); // only used qapp to get parameter easily
	AudioOutputId aid = AudioOutputId_OpenAL;
	int idx = app.arguments().indexof("-ao");
	if(idx > 0)
		aid = AudioOutputFactory::id(app.arguments().at(idx + 1).toUtf8().constData(), false);
	if(!aid) {
		qWarning("unknown backend");
		return -1;
	}
	
}






























































































































































